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


M14_MODULE_ID = "M14"
M14_CONTENT_VERSION = "20260322_m14_lantern_ring_v3"
M14_MODULE_TITLE = "Solar System"
M14_ALLOWLIST = [
    "sun_planet_confusion",
    "planet_category_confusion",
    "dwarf_planet_asteroid_confusion",
    "moon_planet_confusion",
    "comet_asteroid_confusion",
    "gravity_random_motion_confusion",
    "orbit_track_confusion",
    "rotation_orbit_confusion",
    "day_night_sun_motion_confusion",
    "season_distance_confusion",
    "tilt_direction_confusion",
    "hemisphere_season_confusion",
    "moon_phase_shadow_confusion",
    "moon_self_light_confusion",
    "quarter_moon_name_confusion",
    "outer_orbit_same_period_confusion",
    "orbital_distance_period_confusion",
]


def safe_tags(tags: Sequence[str]) -> List[str]:
    allowed = set(M14_ALLOWLIST)
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
    title: str,
    purpose: str,
    caption: str,
    *,
    diagram_type: str,
    meta: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    resolved_meta = {"diagram_type": diagram_type, **deepcopy(meta or {})}
    return {
        "asset_id": asset_id,
        "concept": "astronomy_diagram",
        "phase_key": "analogical_grounding",
        "title": title,
        "purpose": purpose,
        "caption": caption,
        "template": "astronomy_diagram",
        "meta": resolved_meta,
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
        "Sun, orbit, axis, and companion labels remain separated so the geometry stays readable.",
        "Lighted and shadowed regions stay visually distinct before any text explanation is added.",
        "Comparison captions stay outside the busiest orbital paths so the astronomy idea remains easy to parse.",
    ]


def lantern_ring_map(focus: str) -> Dict[str, Any]:
    return {
        "model_name": "Lantern-Ring Model of the Solar System",
        "focus": focus,
        "comparison": f"The Lantern-Ring world keeps the Sun, gravity, orbits, rotation, tilt, phases, and orbital periods inside one lit-and-pulled story while {focus}.",
        "mapping": [
            "Great Lantern -> Sun",
            "Ring route -> orbit",
            "World rider -> planet",
            "Small round rider -> dwarf planet",
            "Companion rider -> moon",
            "Rock swarm -> asteroids",
            "Ice visitor -> comet",
            "Hub pull -> gravity",
            "Spin rod -> rotation axis",
            "Tilt rod -> axial tilt",
            "Year lap -> orbital period",
            "Companion-face phase -> Moon phase",
        ],
        "limit": "The Lantern-Ring story makes the geometry intuitive, but learners still need the formal astronomy terms rotation, orbit, axial tilt, phase, gravity, and orbital period.",
        "prediction_prompt": f"Use the Lantern-Ring model to predict what should happen when {focus}.",
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
    scaffold_support: Dict[str, Any] | None = None,
    visual_clarity_checks: Sequence[str] | None = None,
    assessment_bank_targets: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    payload = {
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
    }
    payload["assessment_bank_targets"] = deepcopy(assessment_bank_targets or assessment_targets())
    if scaffold_support:
        payload["scaffold_support"] = deepcopy(scaffold_support)
    if visual_clarity_checks:
        payload["visual_clarity_checks"] = list(visual_clarity_checks)
    return payload


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
    resolved_contract = deepcopy(contract_payload)
    declared_skills = [
        str(skill).strip()
        for skill in resolved_contract.get("mastery_skills") or []
        if str(skill).strip()
    ]
    for item in [*diagnostic, *capsule_checks, *transfer]:
        for skill in item.get("skill_tags") or []:
            cleaned = str(skill).strip()
            if cleaned and cleaned not in declared_skills:
                declared_skills.append(cleaned)
    resolved_contract["mastery_skills"] = declared_skills
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
        "contract": resolved_contract,
    }


def build_mcqs(rows: Sequence[Tuple[str, str, Sequence[str], int, str, Sequence[str], Sequence[str]]]) -> List[Dict[str, Any]]:
    return [
        mcq(qid, prompt, choices, answer_index, hint, tags, skill_tags=skill_tags)
        for qid, prompt, choices, answer_index, hint, tags, skill_tags in rows
    ]


def build_shorts(
    rows: Sequence[Tuple[str, str, Sequence[str], str, Sequence[str], Sequence[str], Dict[str, Any]]]
) -> List[Dict[str, Any]]:
    return [
        short(
            qid,
            prompt,
            accepted_answers,
            hint,
            tags,
            skill_tags=skill_tags,
            acceptance_rules=acceptance_rules,
        )
        for qid, prompt, accepted_answers, hint, tags, skill_tags, acceptance_rules in rows
    ]


# Lesson authoring content appended below.


def lesson_one() -> Dict[str, Any]:
    diagnostic = build_mcqs([
        ("M14L1_D1", "In the Lantern-Ring model, the Great Lantern stands for the...", ["Sun", "Moon", "largest planet", "Milky Way"], 0, "The Great Lantern is the Sun.", ["sun_planet_confusion"], ["identify_sun"]),
        ("M14L1_D2", "A world rider is a...", ["planet", "moon", "asteroid", "star"], 0, "World riders are planets.", ["planet_category_confusion"], ["classify_planet"]),
        ("M14L1_D3", "A companion rider is a...", ["moon", "planet", "asteroid", "comet"], 0, "Companion riders are moons.", ["moon_planet_confusion"], ["classify_moon"]),
        ("M14L1_D5", "Which body mainly orbits a larger world instead of the Sun?", ["moon", "dwarf planet", "comet", "asteroid"], 0, "A moon mainly orbits a larger world.", ["moon_planet_confusion"], ["classify_moon"]),
        ("M14L1_D6", "How many of these are small-body categories in the Solar Court: asteroid, comet, Sun, Moon?", ["2", "1", "3", "4"], 0, "Asteroid and comet are the two small-body categories in that list.", ["comet_asteroid_confusion"], ["classify_small_bodies", "category_counting"]),
        ("M14L1_D7", "A round body that mainly orbits the Sun but is not counted as a full planet is best classified as a...", ["dwarf planet", "moon", "star", "companion rider"], 0, "That description fits a dwarf planet.", ["dwarf_planet_asteroid_confusion"], ["classify_dwarf_planet"]),
        ("M14L1_D8", "How many of these mainly orbit the Sun directly: planet, dwarf planet, comet, moon?", ["3", "1", "2", "4"], 0, "Planet, dwarf planet, and comet mainly orbit the Sun.", ["moon_planet_confusion", "planet_category_confusion"], ["host_counting"]),
        ("M14L1_D9", "Which statement is strongest?", ["A comet can orbit the Sun without being a planet.", "Anything orbiting the Sun must be a planet.", "Moons are just small planets.", "Asteroids make their own light."], 0, "Sun-orbiting is not enough to make an object a planet.", ["planet_category_confusion", "comet_asteroid_confusion"], ["solar_family"]),
    ]) + build_shorts([
        ("M14L1_D4", "Why is the Solar System stronger as one Sun-centered family than as a random object list?", ["Because the Sun is the central star and its gravity organizes planets, moons, asteroids, comets, and dwarf planets into one system.", "Because one central Sun and its gravity tie the different body types into one family."], "Use center-and-gravity language.", ["sun_planet_confusion"], ["solar_family"], acceptance_groups(["Sun", "central"], ["gravity", "pull"], ["family", "system"], ["planets", "moons", "asteroids", "comets", "dwarf planets"])),
        ("M14L1_D10", "Why is it weak to call every Sun-orbiting body a planet?", ["Because moons, asteroids, comets, and dwarf planets are different categories, so Sun-orbiting alone is not enough to make something a planet.", "Because the Solar Court contains several Sun-centered body types, not just planets."], "Use category language, not only orbit language.", ["planet_category_confusion"], ["solar_family", "classify_planet"], acceptance_groups(["not everything", "not every"], ["Sun-orbiting", "orbits the Sun"], ["planet"], ["different categories", "dwarf planets", "asteroids", "comets"]))
    ])
    concept = build_mcqs([
        ("M14L1_C1", "Which pair both orbit the Sun directly?", ["planet and dwarf planet", "moon and planet", "moon and moon", "moon and asteroid"], 0, "Planets and dwarf planets both orbit the Sun.", ["planet_category_confusion", "moon_planet_confusion"], ["solar_family"]),
        ("M14L1_C2", "Which statement best distinguishes a comet from an asteroid?", ["Comets are icy visitors, while asteroids are mainly rocky small bodies.", "Comets are always planets.", "Asteroids make their own light.", "Comets orbit Earth as companions."], 0, "The key contrast is icy versus mainly rocky.", ["comet_asteroid_confusion"], ["classify_small_bodies"]),
        ("M14L1_C4", "If an object mainly orbits Jupiter, which category is strongest in this module?", ["moon", "planet", "comet", "Sun"], 0, "Mainly orbiting a larger world points to moon.", ["moon_planet_confusion"], ["classify_moon"]),
        ("M14L1_C5", "Which Solar Court statement is strongest?", ["A dwarf planet can orbit the Sun directly without being a full planet.", "A dwarf planet must orbit a planet.", "A comet is a moon with ice.", "An asteroid is a star fragment that makes light."], 0, "Dwarf planets are Sun-orbiting but still a distinct category.", ["dwarf_planet_asteroid_confusion", "planet_category_confusion"], ["classify_dwarf_planet"]),
        ("M14L1_C6", "How many categories are named here: planet, moon, asteroid, comet?", ["4", "2", "3", "5"], 0, "Those are four different Solar Court categories.", ["planet_category_confusion"], ["category_counting"]),
        ("M14L1_C7", "Which pair is best contrasted by 'icy visitor' versus 'rocky small body'?", ["comet and asteroid", "planet and moon", "Sun and comet", "moon and dwarf planet"], 0, "That contrast is comet versus asteroid.", ["comet_asteroid_confusion"], ["classify_small_bodies"]),
    ]) + build_shorts([
        ("M14L1_C3", "Why is a moon not the same category as a planet?", ["Because a moon mainly orbits a planet or dwarf planet, while a planet orbits the Sun directly.", "Because moons are companion riders around larger worlds, not world riders around the Sun."], "Contrast what each one mainly orbits.", ["moon_planet_confusion"], ["classify_moon", "classify_planet"], acceptance_groups(["moon", "companion"], ["orbits"], ["planet", "larger world"], ["planet"], ["Sun", "directly"])),
        ("M14L1_C8", "Why is main host such a useful clue when sorting Solar Court bodies?", ["Because what a body mainly orbits helps distinguish planets and dwarf planets from moons.", "Because host relationship is one of the quickest ways to classify a body in the Solar Court."], "Use host-and-category language together.", ["moon_planet_confusion", "planet_category_confusion"], ["solar_family", "main_host_reasoning"], acceptance_groups(["host", "mainly orbits"], ["distinguish", "sort", "classify"], ["planet", "dwarf planet", "moon"]))
    ])
    mastery = build_mcqs([
        ("M14L1_M1", "Which body is the main light source in the Solar System?", ["Sun", "Moon", "Jupiter", "comet"], 0, "The Sun is the Great Lantern.", ["sun_planet_confusion"], ["identify_sun"]),
        ("M14L1_M2", "Which body is most likely an ice visitor?", ["comet", "Mercury", "Moon", "Sun"], 0, "Ice visitors are comets.", ["comet_asteroid_confusion"], ["classify_small_bodies"]),
        ("M14L1_M3", "Which statement is strongest?", ["Not everything orbiting the Sun is a planet.", "Everything orbiting the Sun is a planet.", "Moons orbit the Sun the same way planets do.", "The Sun is a companion rider."], 0, "The Solar System contains several object categories.", ["planet_category_confusion"], ["solar_family"]),
        ("M14L1_M5", "Which body pair is strongest as 'planet and companion rider'?", ["Earth and Moon", "Sun and comet", "asteroid and comet", "Mars and dwarf planet"], 0, "A planet and its moon fit that pair.", ["moon_planet_confusion"], ["classify_planet", "classify_moon"]),
        ("M14L1_M6", "How many of these are not planets: Moon, comet, dwarf planet, Jupiter?", ["3", "2", "1", "4"], 0, "Moon, comet, and dwarf planet are not planets.", ["planet_category_confusion", "moon_planet_confusion"], ["category_counting"]),
        ("M14L1_M7", "Which rule best sorts a moon from a planet?", ["main host", "surface color", "brightness in the sky", "distance from Earth only"], 0, "Main host is the strongest sorting clue here.", ["moon_planet_confusion"], ["main_host_reasoning"]),
        ("M14L1_M8", "Which object can orbit the Sun directly without being a planet?", ["dwarf planet", "Moon", "Sun", "companion rider"], 0, "A dwarf planet fits that description.", ["dwarf_planet_asteroid_confusion"], ["classify_dwarf_planet"]),
        ("M14L1_M9", "Which statement best protects the category idea?", ["The Solar Court contains several body types tied together by the Sun, not one single planet label.", "Every small body is either a moon or a planet.", "Comets and asteroids are the same thing.", "Only planets belong in the Solar System."], 0, "Keep family and category together.", ["planet_category_confusion", "comet_asteroid_confusion"], ["solar_family"]),
    ]) + build_shorts([
        ("M14L1_M4", "Summarize the Solar System in one strong Lantern-Ring sentence.", ["The Solar System is one Sun-centered family in which planets, dwarf planets, moons, asteroids, and comets move under the Sun's gravity.", "One Great Lantern sits at the center while many different riders move around it under hub pull."], "Keep the Sun-centered family and gravity together.", ["sun_planet_confusion"], ["solar_family"], acceptance_groups(["Sun", "Great Lantern", "center"], ["family", "system"], ["gravity", "hub pull"], ["planets", "moons", "asteroids", "comets", "dwarf planets"])),
        ("M14L1_M10", "Give one clean sorting rule that separates planets from moons in the Solar Court.", ["Planets mainly orbit the Sun, while moons mainly orbit larger worlds.", "The main host separates world riders from companion riders."], "Use main-host language clearly.", ["moon_planet_confusion"], ["main_host_reasoning", "classify_planet", "classify_moon"], acceptance_groups(["planet", "world rider"], ["Sun", "mainly orbits the Sun"], ["moon", "companion rider"], ["larger world", "planet"]))
    ])
    return lesson_spec(
        "M14_L1",
        "Build the Solar Court",
        sim("m14_solar_court_sort_lab", "Solar court sorter", "Sort Solar System bodies so the Sun-centered family becomes one coherent court.", ["Sort bodies by category.", "Keep the Sun at the center.", "Explain why not everything is a planet."], ["Describe the Solar System as one family.", "Distinguish key body categories."], ["object_type", "main_host", "category_sort"], "Solar family classification reasoning."),
        diagnostic,
        "The Solar System is a dark court lit by one Great Lantern. Around that center move world riders, companion riders, rock swarm pieces, ice visitors, and smaller round riders. Some of those smaller round riders orbit the Sun directly but still stay in the dwarf-planet category because they have not cleared their orbital neighborhood like the full planets have.",
        "Commit to the Solar System as one organized Sun-centered family, and use main host plus body-type clues before you call something a planet.",
        [
            prompt_block("What sits at the center of the Solar Court?", "The Great Lantern, which stands for the Sun."),
            prompt_block("What makes a moon different from a planet?", "A moon mainly orbits a larger world instead of the Sun as its main host."),
            prompt_block("What extra clue separates a dwarf planet from a full planet when both orbit the Sun?", "A dwarf planet has not cleared its orbital neighborhood the way a full planet has."),
        ],
        [
            prompt_block("Sort the bodies by what they orbit.", "Planets and dwarf planets orbit the Sun; moons orbit larger worlds."),
            prompt_block("Compare rocky and icy small bodies.", "Asteroids are mainly rocky; comets are icy visitors."),
            prompt_block("Compare a planet with a dwarf planet that both orbit the Sun.", "Use the neighborhood-clearing clue to keep the categories distinct."),
        ],
        [
            "Why is a family model stronger than a loose list of space objects?",
            "Why is it weak to call every Sun-orbiting body a planet?",
            "What extra clue separates a dwarf planet from a full planet when both orbit the Sun?",
        ],
        "Build the family structure first so later lessons on gravity, day, seasons, phases, and years all have a clear home.",
        concept,
        mastery,
        contract(
            concept_targets=[
                "Describe the Solar System as one Sun-centered family.",
                "Distinguish planets, dwarf planets, moons, asteroids, and comets.",
                "Use the neighborhood-clearing clue to separate a dwarf planet from a full planet when both orbit the Sun.",
            ],
            core_concepts=[
                "The Sun is the central star of the Solar System.",
                "Planets and dwarf planets orbit the Sun, while moons orbit larger worlds.",
                "A dwarf planet can orbit the Sun directly and still stay distinct because it has not cleared its orbital neighborhood like a full planet has.",
                "Asteroids are mainly rocky small bodies, while comets are icy visitors.",
                "Object categories matter because not everything orbiting the Sun is a planet.",
            ],
            prerequisite_lessons=[],
            misconception_focus=["sun_planet_confusion", "planet_category_confusion", "moon_planet_confusion", "comet_asteroid_confusion"],
            formulas=[
                relation("Solar System = one Sun-centered family", "Conceptual family rule for the module.", ["concept only"], "Use as the organizing statement."),
                relation("planet or dwarf planet -> orbits Sun", "Main-host rule for Sun-orbiting worlds.", ["concept only"], "Use when sorting planets and dwarf planets from moons."),
                relation("dwarf planet -> round + orbits Sun + not cleared neighborhood", "Adds the extra sorting clue that keeps dwarf planets distinct from the full planets.", ["concept only"], "Use qualitatively in lesson 1 before the worked example and later assessment items."),
            ],
            representations=[representation("words", "Names the Sun-centered family and the main body groups."), representation("diagram", "Shows the Great Lantern, world riders, companion riders, rock swarm, and ice visitor."), representation("formula", "Uses short concept rules for what orbits the Sun and what orbits a larger world.")],
            analogy_map=lantern_ring_map("the learner sorts planets, dwarf planets, moons, asteroids, and comets inside one Solar Court"),
            worked_examples=[worked("A round body orbits the Sun but has not cleared its orbital neighborhood. How should it be classified?", ["Notice that the body orbits the Sun directly.", "Notice that it is round.", "Use the taught neighborhood-clearing clue to keep it separate from the full planets."], "It should be classified as a dwarf planet.", "A dwarf planet is a round Sun-orbiting world that has not cleared its neighborhood.", "This protects learners from collapsing dwarf planets into either planets or asteroids."), worked("A small body mainly orbits Earth rather than the Sun. What category fits best?", ["Ask what the body mainly orbits.", "Notice that its main host is a planet.", "Use the companion-rider rule."], "It is a moon.", "A moon is a companion rider that mainly orbits a larger world.", "This keeps planets and moons separated by orbit relationship."), worked("A learner points to a comet and says, 'It orbits the Sun, so it must be a planet.' How do you correct that?", ["Keep the Sun-orbit clue in place.", "Add the icy small-body category clue.", "Use category and host together."], "A comet is still a comet, not a planet, even though it orbits the Sun.", "Main host alone does not erase the object's body type.", "This strengthens the idea that the Solar Court needs both family structure and category labels.")],
            visual_assets=[visual("m14-l1-solar-court", "Build the Solar Court", "Show the Solar System as one Sun-centered family with several classes of bodies.", "The Solar Court visual keeps planets, dwarf planets, moons, asteroids, and comets together in one organized family.", diagram_type="solar_court")],
            animation_assets=[],
            simulation_contract=sim_contract("m14_l1_solar_court_sim", "solar_court_sort", "Sort each body into the right Solar Court category before explaining why it belongs there.", "Start with one example of each body type around the Great Lantern.", ["Sort by what the body is.", "Sort by what it mainly orbits."], "Watch for the difference between a world orbiting the Sun and a companion orbiting a larger world.", "The Solar System is one Sun-centered family made of several distinct object groups.", controls=[("object_type", "Body selector", "Lets learners compare planets, moons, asteroids, comets, and dwarf planets."), ("main_host", "Main host", "Shows whether the body mainly belongs to the Sun or to a larger world.")], readouts=[("Current classification", "Names the most accurate Solar Court category."), ("Host note", "Shows what the selected body mainly orbits.")]),
            reflection_prompts=["Explain why the Solar System is stronger as one Sun-centered family than as a random list of objects."],
            mastery_skills=["solar_family", "identify_sun", "classify_planet", "classify_dwarf_planet", "classify_moon", "classify_small_bodies", "main_host_reasoning", "category_counting"],
            variation_plan={"diagnostic": "Fresh attempts rotate between Sun-role, category, and main-host prompts.", "concept_gate": "Concept-gate retries alternate between category corrections, neighborhood-clearing explanations, and short host-orbit explanations.", "mastery": "Mastery varies summary, counting, and classification prompts before repeating a previous family."},
            scaffold_support=scaffold(
                "Start with one central Sun and sort everything else by category, main host, and the dwarf-planet neighborhood clue.",
                "Ask first what the body is, then ask what it mainly orbits, and finally use the neighborhood-clearing clue when you need to separate a dwarf planet from a full planet.",
                "Which clue is stronger for separating planets from moons: color or main host?",
                "Do not let 'orbits the Sun' collapse every body into the planet label.",
                "The Solar Court works because one Great Lantern can organize several body categories without making them identical.",
                "What extra clue does the Solar Court need when two round bodies both orbit the Sun?",
                [
                    extra_section("Host Rule", "Main host is the quickest sorting clue for separating world riders from companion riders.", "Which body type mainly orbits a larger world?"),
                    extra_section("Dwarf Planet Rule", "A dwarf planet can orbit the Sun directly and still stay distinct from the full planets because it has not cleared its orbital neighborhood.", "What extra clue separates a dwarf planet from a full planet?"),
                    extra_section("Small Bodies", "Asteroids and comets belong in the same family but still need rocky-versus-icy distinctions.", "Why is a comet not just an asteroid with a longer orbit?"),
                ],
            ),
            visual_clarity_checks=visual_checks("Solar Court"),
        ),
    )


def lesson_two() -> Dict[str, Any]:
    diagnostic = build_mcqs([
        ("M14L2_D1", "In the Lantern-Ring model, hub pull stands for...", ["gravity", "sunlight", "air resistance", "moonlight"], 0, "Hub pull is gravity.", ["gravity_random_motion_confusion"], ["identify_gravity"]),
        ("M14L2_D2", "A ring route stands for an...", ["orbit", "axis tilt", "day-night line", "phase shadow"], 0, "Ring routes are orbits.", ["orbit_track_confusion"], ["identify_orbit"]),
        ("M14L2_D3", "Which statement is strongest?", ["Orbits are pull-guided paths, not metal tracks in space.", "Orbits are rigid rails attached to the Sun.", "Planets need engines to stay in orbit.", "Gravity matters only for the Moon."], 0, "An orbit is a gravity-shaped path, not a solid rail.", ["orbit_track_confusion"], ["orbit_reasoning"]),
        ("M14L2_D5", "If hub pull increases while forward motion stays the same, the route should become...", ["more curved", "completely straight", "motionless", "brighter"], 0, "Stronger inward pull bends the route more strongly.", ["gravity_random_motion_confusion"], ["orbit_shape_compare"]),
        ("M14L2_D6", "If forward motion increases while hub pull stays the same, the route is most likely to become...", ["wider", "more tightly bent", "a fixed rail", "a season cycle"], 0, "More forward motion with the same pull gives a wider route.", ["orbit_track_confusion"], ["orbit_shape_compare"]),
        ("M14L2_D7", "Which pair is strongest as the same gravity story?", ["Earth around the Sun and Moon around Earth", "day and night", "summer and winter", "new moon and full moon"], 0, "Both are gravity-guided orbits.", ["gravity_random_motion_confusion"], ["moon_gravity"]),
        ("M14L2_D8", "If the inward pull vanished but forward motion stayed, the body would most likely keep moving...", ["more straight ahead", "in a tighter orbit", "nowhere", "toward the Moon"], 0, "Without the inward pull, the path would stop curving inward.", ["gravity_random_motion_confusion"], ["orbit_reasoning"]),
        ("M14L2_D9", "Which statement best protects against the engine myth?", ["A planet can keep orbiting because gravity keeps bending its forward motion.", "Planets must fire engines constantly to stay up.", "Only the Sun can move in space.", "Orbits exist only because space contains metal rails."], 0, "Gravity plus motion is enough for the basic orbit story.", ["orbit_track_confusion", "gravity_random_motion_confusion"], ["orbit_reasoning"]),
    ]) + build_shorts([
        ("M14L2_D4", "Why does a planet keep going around the Sun instead of only falling inward?", ["Because the planet has forward motion while gravity keeps turning that motion inward, so the path becomes an orbit.", "Because forward motion and the Sun's pull combine to make a curved ring route instead of a straight fall."], "Combine forward motion with gravity.", ["gravity_random_motion_confusion", "orbit_track_confusion"], ["orbit_reasoning"], acceptance_groups(["forward motion"], ["gravity", "hub pull"], ["curved path", "orbit"], ["not just fall"])),
        ("M14L2_D10", "Why is it weak to describe an orbit as a rigid track?", ["Because the orbit is a path created by gravity and forward motion, not a built rail in space.", "Because the route exists as caused motion rather than as a physical structure."], "Use caused-path language.", ["orbit_track_confusion"], ["identify_orbit", "orbit_reasoning"], acceptance_groups(["orbit", "route"], ["path", "caused motion"], ["not", "rather than"], ["track", "rail", "built structure"])),
    ])
    concept = build_mcqs([
        ("M14L2_C1", "Which force organizes both planets around the Sun and moons around planets?", ["gravity", "friction", "magnetism", "sound"], 0, "Gravity is the shared organizing pull.", ["gravity_random_motion_confusion"], ["moon_gravity"]),
        ("M14L2_C2", "If a moving body is continually pulled inward while it also keeps moving forward, the best path description is...", ["curved", "still", "random", "vertical"], 0, "That is the core orbit idea.", ["gravity_random_motion_confusion"], ["orbit_reasoning"]),
        ("M14L2_C4", "If forward motion halves while the inward pull stays the same, the route should become...", ["more tightly curved", "less curved", "flat", "a phase pattern"], 0, "Less forward motion with the same pull gives a tighter curve.", ["gravity_random_motion_confusion"], ["orbit_shape_compare"]),
        ("M14L2_C5", "A route is less curved than before while hub pull is unchanged. The strongest explanation is that...", ["forward motion is greater", "gravity has vanished", "the Sun is smaller", "it became a moon"], 0, "Greater forward motion makes the route wider if pull is unchanged.", ["gravity_random_motion_confusion"], ["orbit_shape_compare"]),
        ("M14L2_C6", "Which description best matches hub pull working on a moving world?", ["continuous inward turning", "one single shove at the start", "light production", "shadow making"], 0, "Gravity keeps turning the motion inward.", ["gravity_random_motion_confusion"], ["identify_gravity"]),
        ("M14L2_C7", "Which comparison best shows that orbits are caused paths rather than tracks?", ["Change the pull or forward motion and the route changes", "Paint the orbit line brighter", "Move the Moon closer to Earth only once", "Change the season"], 0, "A caused path changes when the motion conditions change.", ["orbit_track_confusion"], ["orbit_reasoning"]),
    ]) + build_shorts([
        ("M14L2_C3", "Why does the same gravity idea work for both planets and moons?", ["Because gravity can guide any orbiting body, so the Sun holds planets and planets hold moons.", "Because hub pull is the same basic kind of attraction whether the central body is the Sun or a planet."], "Name both Sun-planets and planet-moons.", ["gravity_random_motion_confusion"], ["moon_gravity", "identify_gravity"], acceptance_groups(["gravity", "hub pull"], ["Sun", "planets"], ["planet", "moons"], ["same basic idea", "works for both"])),
        ("M14L2_C8", "Why does inward pull alone not make the full orbit story?", ["Because forward motion is also needed; gravity bends that motion into a curved path instead of letting the world just fall straight in.", "Because an orbit needs both forward motion and inward pull working together."], "Keep both ingredients visible.", ["gravity_random_motion_confusion"], ["orbit_reasoning"], acceptance_groups(["forward motion"], ["gravity", "inward pull", "hub pull"], ["curved path", "orbit"], ["not just fall", "not only fall"])),
    ])
    mastery = build_mcqs([
        ("M14L2_M1", "Best one-line summary of a ring route:", ["a pull-guided orbit shaped by gravity", "a bright stripe made of sunlight", "a rigid metal circle in space", "the Moon's shadow"], 0, "Keep the orbit definition short and physical.", ["orbit_track_confusion"], ["identify_orbit"]),
        ("M14L2_M2", "Which statement best protects against the track misconception?", ["The orbit is a path produced by gravity and motion, not a built structure.", "The orbit is a strong wire holding the planet up.", "The planet moves only because the Sun drags it around.", "Only circles count as orbits."], 0, "Use gravity-and-motion language.", ["orbit_track_confusion"], ["identify_orbit"]),
        ("M14L2_M3", "Which object pair is best explained by the same gravity story?", ["Earth around the Sun and the Moon around Earth", "day and night", "summer and winter", "new moon and full moon"], 0, "Both are gravity-guided orbits.", ["gravity_random_motion_confusion"], ["moon_gravity"]),
        ("M14L2_M5", "If the same world keeps the same forward motion but the Sun's pull is stronger, the route should be...", ["more curved", "more like a straight line", "completely stationary", "a Moon phase"], 0, "Stronger inward pull bends the route more.", ["gravity_random_motion_confusion"], ["orbit_shape_compare"]),
        ("M14L2_M6", "If two worlds have the same pull but one completes a much wider route, the strongest explanation is that the wider-route world has...", ["more forward motion", "less forward motion", "no gravity", "a shorter year only"], 0, "A wider route at the same pull points to greater forward motion.", ["gravity_random_motion_confusion"], ["orbit_shape_compare"]),
        ("M14L2_M7", "Which line best explains why a planet does not need a metal track to orbit?", ["Gravity keeps redirecting the moving planet, so the route is produced continuously.", "The orbit was built when the Solar System formed and has stayed solid.", "The track is invisible because it is made of cold light.", "The Moon holds each planet in place."], 0, "Use ongoing redirection, not hidden structure.", ["orbit_track_confusion"], ["orbit_reasoning"]),
        ("M14L2_M8", "Which change would usually make the path least curved?", ["increase forward motion while keeping pull the same", "increase pull while keeping motion the same", "remove the Sun from the Solar System list", "rename the orbit"], 0, "More forward motion with the same pull widens the path.", ["gravity_random_motion_confusion"], ["orbit_shape_compare"]),
        ("M14L2_M9", "Which statement is strongest?", ["Gravity plus motion explains both how the path curves and why it is not a rail.", "An orbit is best imagined as a glowing circle in space.", "The Sun decides the path without the moving body's motion mattering.", "Planets orbit only because space has a preferred circle."], 0, "Use gravity-plus-motion as the whole explanation.", ["orbit_track_confusion"], ["orbit_reasoning"]),
    ]) + build_shorts([
        ("M14L2_M4", "Summarize why planets orbit the Sun in one strong sentence.", ["Planets orbit because their forward motion and the Sun's gravity combine to make curved paths around the Sun.", "A planet keeps moving forward while the Sun's pull keeps bending the path into an orbit."], "Keep forward motion and gravity together.", ["gravity_random_motion_confusion", "orbit_track_confusion"], ["orbit_reasoning"], acceptance_groups(["forward motion"], ["gravity", "Sun's pull", "hub pull"], ["curved path", "orbit"], ["around the Sun"])),
        ("M14L2_M10", "Explain in one sentence why a moon around a planet and a planet around the Sun can share the same orbit idea.", ["Because both keep moving forward while gravity from a central body bends the path into an orbit.", "Because the host body changes, but the same gravity-plus-motion rule still works."], "Name the shared rule, not just the two examples.", ["gravity_random_motion_confusion"], ["moon_gravity", "orbit_reasoning"], acceptance_groups(["gravity", "hub pull"], ["forward motion"], ["Sun or planet", "central body"], ["orbit", "curved path", "same rule"])),
    ])
    return lesson_spec(
        "M14_L2",
        "Hub Pull and Ring Routes",
        sim("m14_hub_pull_routes_lab", "Hub pull routes lab", "Change pull strength and forward motion so orbits become gravity-guided paths rather than rigid tracks.", ["Compare weaker and stronger inward pull.", "Compare slower and faster forward motion.", "Explain why moons and planets both fit the same basic orbit story."], ["Explain orbits as gravity-shaped motion.", "Distinguish pull-guided paths from rigid tracks."], ["pull_strength", "forward_motion", "orbit_shape"], "Orbit reasoning with gravity and forward motion."),
        diagnostic,
        "Ring routes are pull-guided paths made by the hub pull of gravity. A world rider keeps moving forward while the hub pull keeps turning that motion inward, so the rider loops around the Great Lantern instead of flying away or falling straight in.",
        "Commit to orbits as gravity-guided motion instead of fixed rails.",
        [prompt_block("What does hub pull stand for?", "Gravity."), prompt_block("Why is a ring route not a physical track?", "Because the route is shaped by gravity and motion, not built as a rail.")],
        [prompt_block("Compare a stronger inward pull with the same forward motion.", "The path should curve more strongly."), prompt_block("Compare the Moon around Earth with Earth around the Sun.", "The same gravity idea guides both.")],
        ["Why is an orbit better understood as a path than as a track?", "Why does the same gravity story work for planets and moons?"],
        "Use the hub-pull story before introducing the later Earth-Sun-Moon geometry lessons.",
        concept,
        mastery,
        contract(
            concept_targets=["Explain orbits as gravity-guided motion rather than rigid tracks.", "Describe how forward motion and gravity combine to make curved paths."],
            core_concepts=["Gravity is the hub pull that shapes orbital motion.", "An orbit is a repeated path, not a physical rail in space.", "Forward motion and inward pull combine to make a curved route.", "The same gravity story explains planets around the Sun and moons around planets."],
            prerequisite_lessons=["M14_L1"],
            misconception_focus=["gravity_random_motion_confusion", "orbit_track_confusion"],
            formulas=[relation("orbit path = forward motion + hub pull", "Conceptual orbit rule for the module.", ["concept only"], "Use before formal orbital mechanics.")],
            representations=[representation("words", "Explains orbits through gravity and forward motion."), representation("diagram", "Shows a world rider, hub pull arrow, and forward motion arrow."), representation("formula", "Compresses the orbit idea into a short conceptual relation.")],
            analogy_map=lantern_ring_map("the learner explains why planets and moons follow pull-guided ring routes"),
            worked_examples=[worked("A learner says, 'The orbit must be a built track in space.' How do you correct that idea?", ["Ask what actually provides the turning effect.", "Replace the track picture with gravity plus forward motion.", "Restate the orbit as a path rather than a structure."], "The orbit is a gravity-guided path, not a built track.", "The curve comes from the inward pull acting while the body keeps moving forward.", "This protects the learner from carrying a rail-model misconception into later astronomy lessons."), worked("Why can the same idea explain Earth around the Sun and the Moon around Earth?", ["Identify the central body in each case.", "Notice that gravity is the pull in both cases.", "State the shared orbit rule."], "Both are gravity-guided orbits around a central body.", "The host body changes, but the same hub-pull idea keeps working.", "This helps the learner reuse one orbit principle instead of memorizing two unrelated stories."), worked("Hub pull stays the same but forward motion becomes larger. What happens to the route qualitatively?", ["Keep the inward pull unchanged.", "Increase the onward motion part of the story.", "Compare how tightly the path bends."], "The route becomes wider and less tightly curved.", "With the same pull acting on more forward motion, the path bends less sharply.", "This helps learners connect parameter changes to orbit shape instead of memorizing only words.")],
            visual_assets=[visual("m14-l2-hub-pull-routes", "Hub pull and ring routes", "Show how gravity and forward motion cooperate to shape an orbit without any physical rail in space.", "The ring-route visual keeps the orbit tied to pull and motion so the path feels caused rather than built.", diagram_type="gravity_rings")],
            animation_assets=[],
            simulation_contract=sim_contract("m14_l2_hub_pull_routes_sim", "hub_pull_routes", "Change pull strength and forward motion until the ring route makes sense as a gravity-shaped path.", "Start with one world rider moving around the Great Lantern on a stable ring route.", ["Raise the pull strength.", "Lower the forward motion."], "Watch for the route changing because the path is caused by gravity and motion together.", "An orbit is a pull-guided path rather than a built track in space.", controls=[("pull_strength", "Hub pull", "Changes how strongly the route bends inward."), ("forward_motion", "Forward motion", "Sets how strongly the body keeps moving along the path.")], readouts=[("Orbit shape", "Summarizes how curved the current route is."), ("Reasoning note", "Keeps the learner focused on gravity plus motion instead of track language.")]),
            reflection_prompts=["Explain why a ring route is stronger as a pull-guided path than as a fixed track."],
            mastery_skills=["identify_gravity", "identify_orbit", "orbit_reasoning", "moon_gravity", "gravity_motion_bridge"],
            variation_plan={"diagnostic": "Fresh attempts rotate between pull, path, and motion questions.", "concept_gate": "Concept-gate retries alternate between planet-Sun and moon-planet comparisons.", "mastery": "Mastery varies misconception corrections and orbit summaries before repeating an earlier stem."},
            scaffold_support=scaffold(
                "Keep orbit as a caused path built from forward motion plus gravity.",
                "When you explain any orbit, identify the inward pull and the ongoing forward motion before you name the route.",
                "Which idea vanishes if you imagine a rigid rail instead of caused motion?",
                "Do not replace gravity and motion with an invisible track picture.",
                "The Lantern-Ring route is like a runner whose path keeps bending inward because the hub keeps pulling while the runner keeps moving.",
                "Why does the route change when pull or forward motion changes?",
                [
                    extra_section("Two Inputs", "Orbit reasoning needs both forward motion and inward pull on the board at the same time.", "What happens if you mention gravity but forget the forward motion?"),
                    extra_section("Shared Gravity Story", "The same hub-pull logic explains moons around planets and planets around the Sun.", "Which part of the story stays the same when the central body changes?"),
                ],
            ),
            visual_clarity_checks=visual_checks("orbit board"),
        ),
    )


def lesson_three() -> Dict[str, Any]:
    diagnostic = build_mcqs([
        ("M14L3_D1", "In the Lantern-Ring model, spin on a rod stands for...", ["rotation", "orbit", "gravity", "phase"], 0, "Spin on a rod stands for rotation.", ["rotation_orbit_confusion"], ["identify_rotation"]),
        ("M14L3_D2", "Day and night on Earth happen mainly because Earth...", ["rotates", "orbits the Sun once per day", "gets closer to the Sun", "changes Moon phase"], 0, "Day and night come from rotation.", ["rotation_orbit_confusion"], ["day_night_reasoning"]),
        ("M14L3_D3", "If Earth rotates 360 degrees in 24 hours, it turns about how many degrees per hour?", ["15 degrees", "24 degrees", "30 degrees", "6 degrees"], 0, "360 / 24 = 15.", ["rotation_orbit_confusion"], ["rotation_rate"]),
        ("M14L3_D5", "How many hours are in half of one full Earth rotation?", ["12 hours", "6 hours", "18 hours", "24 hours"], 0, "Half of 24 hours is 12 hours.", ["rotation_orbit_confusion"], ["rotation_period"]),
        ("M14L3_D6", "If Earth rotates 180 degrees, about how much time has passed?", ["12 hours", "6 hours", "3 hours", "24 hours"], 0, "180 / 15 = 12 hours.", ["rotation_orbit_confusion"], ["rotation_rate"]),
        ("M14L3_D7", "What local change happens when a place rotates from the dark half into the lit half?", ["sunrise", "winter", "full moon", "eclipse"], 0, "Moving into the lit half corresponds to sunrise.", ["day_night_sun_motion_confusion"], ["day_night_reasoning"]),
        ("M14L3_D8", "Which statement is strongest?", ["The yearly orbit is too slow to explain the 24-hour day-night cycle.", "Earth's yearly orbit causes sunrise each morning.", "The Moon creates day and night.", "Earth is sometimes fully lit."], 0, "Daily change belongs to rotation, not the yearly orbit.", ["rotation_orbit_confusion"], ["rotation_orbit_compare"]),
        ("M14L3_D9", "If Earth rotates 30 degrees, about how much time has passed?", ["2 hours", "4 hours", "8 hours", "10 hours"], 0, "30 / 15 = 2 hours.", ["rotation_orbit_confusion"], ["rotation_rate"]),
    ]) + build_shorts([
        ("M14L3_D4", "Why is it weak to say day and night happen because Earth goes around the Sun?", ["Because Earth's orbit takes about a year, while day and night come from Earth's daily rotation.", "Because the 24-hour cycle is made by spin, not by one yearly trip around the Sun."], "Contrast daily rotation with yearly orbit.", ["rotation_orbit_confusion"], ["day_night_reasoning"], acceptance_groups(["rotation", "spin"], ["24-hour", "daily"], ["orbit", "year"], ["not", "rather than"])),
        ("M14L3_D10", "Why can one side of Earth have day while the other has night at the same time?", ["Because one half of Earth faces the Sun while the opposite half faces away, and the rotating globe carries places between those halves.", "Because Earth is half lit and half dark at any moment, so different places can be in different parts of the cycle."], "Use half-lit world language.", ["day_night_sun_motion_confusion"], ["day_night_reasoning"], acceptance_groups(["half", "one half"], ["faces the Sun", "lit", "sunlight"], ["other half", "opposite"], ["away", "dark", "night"])),
    ])
    concept = build_mcqs([
        ("M14L3_C1", "How many hours are needed for Earth to rotate about 90 degrees?", ["6 hours", "3 hours", "12 hours", "18 hours"], 0, "90 / 15 = 6.", ["rotation_orbit_confusion"], ["rotation_rate"]),
        ("M14L3_C2", "Which phrase best matches the spin rod?", ["rotation axis", "orbit path", "sunlight beam", "phase shadow"], 0, "The spin rod is the rotation axis.", ["rotation_orbit_confusion"], ["identify_rotation"]),
        ("M14L3_C4", "If a place rotates about 120 degrees, roughly how much time has passed?", ["8 hours", "4 hours", "10 hours", "16 hours"], 0, "120 / 15 = 8 hours.", ["rotation_orbit_confusion"], ["rotation_rate"]),
        ("M14L3_C5", "What local event is most likely when a place crosses from the lit half into the dark half?", ["sunset", "summer", "full moon", "noon"], 0, "Crossing into the dark half corresponds to sunset.", ["day_night_sun_motion_confusion"], ["day_night_reasoning"]),
        ("M14L3_C6", "Which statement best matches local noon?", ["the place is most directly turned toward the Sun", "the place is on the night-face", "Earth is closest to the Sun", "the Moon is overhead"], 0, "Noon belongs to the side facing most directly toward the Sun.", ["day_night_sun_motion_confusion"], ["day_night_reasoning"]),
        ("M14L3_C7", "Which comparison best protects against the orbit confusion?", ["24 hours for rotation versus about a year for revolution", "24 hours for the Moon and a year for Earth", "23.4 degrees versus 90 degrees", "new moon versus full moon"], 0, "Use the daily-versus-yearly timescale contrast.", ["rotation_orbit_confusion"], ["rotation_orbit_compare"]),
    ]) + build_shorts([
        ("M14L3_C3", "Explain how rotation creates the day-night cycle.", ["As Earth rotates, a place moves into the lit half and later into the dark half, creating day and night.", "Earth's spin turns places toward the Sun and then away from it, so the local sky changes from day to night."], "Use turn-toward and turn-away language.", ["rotation_orbit_confusion"], ["day_night_reasoning"], acceptance_groups(["rotate", "spin"], ["toward the Sun", "into sunlight"], ["away from the Sun", "dark half"], ["day", "night"])),
        ("M14L3_C8", "Why is the half-lit, half-dark picture useful for the day-night story?", ["Because it shows that different places can be in daylight or darkness at the same time as Earth rotates.", "Because it makes the daily cycle a geometry of one lit half and one dark half."], "Use simultaneous-day-and-night language.", ["day_night_sun_motion_confusion"], ["day_night_reasoning"], acceptance_groups(["half lit", "lit half"], ["half dark", "dark half"], ["same time", "simultaneous"], ["rotation", "spins"])),
    ])
    mastery = build_mcqs([
        ("M14L3_M1", "If Earth turns 45 degrees in the simple model, about how much time has passed?", ["3 hours", "6 hours", "9 hours", "12 hours"], 0, "45 / 15 = 3.", ["rotation_orbit_confusion"], ["rotation_rate"]),
        ("M14L3_M2", "What stays true at every moment in the day-night story?", ["Half of Earth is lit and half is dark.", "All of Earth is lit at noon.", "All of Earth is dark at midnight.", "Only the equator gets sunlight."], 0, "The split between day-face and night-face is always present.", ["day_night_sun_motion_confusion"], ["day_night_reasoning"]),
        ("M14L3_M3", "How many hours are in half of Earth's rotation period?", ["12 hours", "6 hours", "18 hours", "24 hours"], 0, "Half of 24 hours is 12 hours.", ["rotation_orbit_confusion"], ["rotation_period"]),
        ("M14L3_M5", "If Earth turns 270 degrees, about how much time has passed?", ["18 hours", "6 hours", "9 hours", "15 hours"], 0, "270 / 15 = 18 hours.", ["rotation_orbit_confusion"], ["rotation_rate"]),
        ("M14L3_M6", "About how many hours after local noon is local midnight in the simple model?", ["12 hours", "6 hours", "18 hours", "24 hours"], 0, "Half a rotation after noon is midnight.", ["day_night_sun_motion_confusion"], ["rotation_period"]),
        ("M14L3_M7", "Which statement best keeps daily and yearly motion separate?", ["Rotation explains the daily cycle, while the orbit explains the yearly cycle.", "The yearly orbit explains both noon and winter.", "Rotation makes the Moon wax and wane.", "The orbit decides which side of Earth is lit each minute."], 0, "Keep daily and yearly motions distinct.", ["rotation_orbit_confusion"], ["rotation_orbit_compare"]),
        ("M14L3_M8", "If a place rotates 15 degrees, about how much time has passed?", ["1 hour", "2 hours", "4 hours", "15 hours"], 0, "15 degrees per hour means 15 degrees corresponds to about 1 hour.", ["rotation_orbit_confusion"], ["rotation_rate"]),
        ("M14L3_M9", "Which statement is strongest?", ["Sunrise happens because rotation carries a place into sunlight.", "Sunrise happens because Earth reaches a different part of its yearly orbit each morning.", "Sunrise happens because the Sun circles Earth daily.", "Sunrise depends mainly on Moon phase."], 0, "Use rotation carrying a place into sunlight.", ["day_night_sun_motion_confusion"], ["day_night_reasoning"]),
    ]) + build_shorts([
        ("M14L3_M4", "Summarize day and night in one strong sentence.", ["Day and night happen because Earth rotates, so places turn toward the Sun and then away from it.", "The day-night cycle is Earth's spin carrying each place through the lit half and the dark half."], "Keep rotation and facing-toward-away together.", ["rotation_orbit_confusion"], ["day_night_reasoning"], acceptance_groups(["rotation", "spin"], ["toward the Sun", "lit half"], ["away from the Sun", "dark half"], ["day", "night"])),
        ("M14L3_M10", "Explain in one sentence why the yearly orbit cannot be the direct cause of the 24-hour day-night cycle.", ["Because the orbit takes about a year, while the day-night cycle is created by one rotation in about 24 hours.", "Because the timescale for revolution is much too long; the daily cycle comes from spin."], "Use timescale language clearly.", ["rotation_orbit_confusion"], ["rotation_orbit_compare"], acceptance_groups(["orbit", "revolution", "year"], ["24 hours", "daily"], ["rotation", "spin"], ["not", "rather than", "too long"])),
    ])
    return lesson_spec(
        "M14_L3",
        "Spin for Daylight",
        sim("m14_spin_for_daylight_lab", "Spin for daylight lab", "Rotate a home world under one lantern so day-face, night-face, and rotation period become visible.", ["Turn the world through quarter and half rotations.", "Track a city moving into and out of sunlight.", "Compare daily spin with yearly orbit."], ["Explain day and night through rotation.", "Use 24 hours and 15 degrees per hour consistently."], ["rotation_angle", "rotation_rate", "day_side"], "Day-night reasoning through rotation."),
        diagnostic,
        "A world rider does not need to complete a trip around the Great Lantern to make day and night. It only needs to spin. One half faces the lantern while the other faces away, and as the world rotates, each place takes its turn on the day-face and the night-face.",
        "Commit to day and night as a spin story rather than a year-lap story.",
        [prompt_block("What creates the day-night cycle in this model?", "Rotation on the spin rod."), prompt_block("How much of Earth is lit at one moment?", "About half.")],
        [prompt_block("Turn the world through a quarter rotation.", "That represents about 6 hours on Earth."), prompt_block("Track one city across the lit and dark halves.", "The city's local day changes because the world spins.")],
        ["Why is a daily cycle stronger as a rotation idea than as an orbit idea?", "How does the half-lit, half-dark world picture help explain simultaneous day and night?"],
        "Lock down the rotation geometry before moving to the tilted-axis and companion-phase lessons.",
        concept,
        mastery,
        contract(
            concept_targets=["Explain day and night through rotation.", "Use Earth's 24-hour rotation period qualitatively and numerically."],
            core_concepts=["Day and night are created by Earth's rotation.", "At any moment, half of Earth is lit and half is dark.", "A full Earth rotation takes about 24 hours.", "The daily cycle must not be confused with Earth's yearly orbit around the Sun."],
            prerequisite_lessons=["M14_L2"],
            misconception_focus=["rotation_orbit_confusion", "day_night_sun_motion_confusion"],
            formulas=[relation("360 degrees / 24 h = 15 degrees per hour", "Simple Earth-rotation rate used for day-night timing.", ["deg h^-1"], "Use for quarter-turn and half-turn timing.")],
            representations=[representation("words", "Explains day-face and night-face through Earth's spin."), representation("diagram", "Shows a lit half, dark half, and spin rod."), representation("formula", "Uses 15 degrees per hour and 24-hour rotation timing.")],
            analogy_map=lantern_ring_map("the learner explains how a spinning world creates day and night"),
            worked_examples=[worked("Earth rotates 360 degrees in 24 hours. How many degrees does it rotate in 6 hours?", ["Use 360 degrees in 24 hours as 15 degrees per hour.", "Multiply 15 by 6.", "State the quarter-turn result."], "90 degrees", "A quarter of the full 24-hour rotation is 90 degrees.", "This helps learners connect the day-night story to a simple measurable rate."), worked("A learner says, 'Sunrise happens because Earth moves to a new place in its yearly orbit.' How do you correct that?", ["Compare the daily cycle with the yearly orbit time.", "Track one place through one spin.", "Restate sunrise as turning into sunlight."], "Sunrise is caused by rotation, not the yearly orbit.", "The 24-hour change belongs to Earth spinning, while the orbit takes about a year.", "This protects the lesson from collapsing daily and yearly motion into one blurred idea."), worked("If a city marker rotates 120 degrees from its starting position, how much time has passed?", ["Use 15 degrees per hour from the 360 degrees in 24 hours rule.", "Divide 120 by 15.", "State the elapsed time."], "8 hours", "At 15 degrees per hour, 120 degrees corresponds to 8 hours.", "This gives the lesson a second timing route so the rotation rate feels usable, not decorative.")],
            visual_assets=[visual("m14-l3-spin-for-daylight", "Spin for daylight", "Show one lit half, one dark half, and the spin rod so the daily cycle stays tied to rotation.", "The day-night visual keeps the Sun fixed and lets Earth's own spin do the explanatory work.", diagram_type="day_night_rotation")],
            animation_assets=[],
            simulation_contract=sim_contract("m14_l3_spin_for_daylight_sim", "spin_for_daylight", "Rotate the world until the daily cycle feels like a spin story instead of an orbit story.", "Start with a city near the boundary between day-face and night-face.", ["Advance the world by 3 hours.", "Advance the world by 6 hours."], "Watch the city move into sunlight and later back into darkness because of spin, not because of the yearly lap.", "Day and night are produced by Earth's rotation on its axis.", controls=[("rotation_angle", "Rotation angle", "Moves the home world through the lit and dark halves."), ("rotation_rate", "Spin rate", "Helps compare quarter-turn, half-turn, and full-turn timing.")], readouts=[("Local side", "Shows whether the city is on the day-face or night-face."), ("Elapsed time", "Converts the spin angle into approximate hours.")]),
            reflection_prompts=["Explain why day and night are stronger as a spin story than as an orbit story."],
            mastery_skills=["identify_rotation", "rotation_period", "rotation_rate", "day_night_reasoning", "rotation_orbit_compare"],
            variation_plan={"diagnostic": "Fresh attempts rotate between cause-of-day-night and simple rotation-rate questions.", "concept_gate": "Concept-gate retries alternate between city-rotation reasoning and timing calculations.", "mastery": "Mastery varies summary, timing, and misconception-correction tasks before repeating an earlier day-night family."},
            scaffold_support=scaffold(
                "Treat the daily cycle as a spin problem on a half-lit world.",
                "Use the lit half, dark half, and spin rod before you mention any yearly motion.",
                "Which single idea explains sunrise, noon, sunset, and midnight best?",
                "Do not let a daily cycle drift into yearly-orbit language.",
                "The Lantern-Ring world shows that one turning globe can make different local sky conditions at the same time.",
                "Why can opposite sides of Earth have different local times without needing two Suns?",
                [
                    extra_section("Half-Lit Rule", "At any moment one half faces the Sun and one half faces away.", "What local state belongs to the half facing away from the Sun?"),
                    extra_section("Rate Rule", "Earth's rotation rate lets you translate angle turned into elapsed time.", "How many hours go with a quarter turn?"),
                ],
            ),
            visual_clarity_checks=visual_checks("day-night board"),
        ),
    )


def lesson_four() -> Dict[str, Any]:
    diagnostic = build_mcqs([
        ("M14L4_D1", "The main cause of Earth's seasons is...", ["axial tilt", "distance from the Sun changing a lot each season", "Moonlight", "Earth spinning faster in summer"], 0, "Seasons come from axial tilt, not distance.", ["season_distance_confusion"], ["season_reasoning"]),
        ("M14L4_D2", "Earth's axis is tilted by about...", ["23.4 degrees", "90 degrees", "5 degrees", "180 degrees"], 0, "Earth's axial tilt is about 23.4 degrees.", ["tilt_direction_confusion"], ["tilt_value"]),
        ("M14L4_D3", "When the Northern Hemisphere tilts toward the Sun, it is generally...", ["summer there", "winter there", "night all day", "a full moon"], 0, "Tilt toward means more direct sunlight and longer days.", ["hemisphere_season_confusion"], ["season_reasoning"]),
        ("M14L4_D5", "About how many months separate the opposite seasonal positions in this lesson?", ["6 months", "1 month", "3 months", "12 months"], 0, "Opposite seasonal positions are about half a year apart.", ["hemisphere_season_confusion"], ["season_timing"]),
        ("M14L4_D6", "If the Northern Hemisphere is tilted away from the Sun, the Southern Hemisphere is most likely experiencing...", ["summer", "winter", "midnight everywhere", "full moon"], 0, "Opposite hemispheres lean in opposite ways.", ["hemisphere_season_confusion"], ["hemisphere_compare"]),
        ("M14L4_D7", "Which statement is strongest?", ["Sunlight angle matters more than a simple close-far distance idea.", "Summer happens because Earth stops spinning.", "The Moon decides the seasons.", "The Sun moves closer only to one hemisphere."], 0, "Use tilt and sunlight-angle language.", ["season_distance_confusion"], ["season_reasoning"]),
        ("M14L4_D8", "If Earth had no axial tilt, the best simple prediction is...", ["much weaker seasonal contrast", "no orbit at all", "no day and night", "no Moon phases"], 0, "Tilt is the main reason the usual seasonal contrast exists.", ["season_distance_confusion"], ["season_reasoning"]),
        ("M14L4_D9", "Which statement best describes Earth's axis during the year in this module?", ["It keeps roughly the same direction in space.", "It flips to point directly at the Sun each month.", "It lies flat in the orbital plane.", "It spins around the Moon."], 0, "The same tilt direction in space is central to the season story.", ["tilt_direction_confusion"], ["tilt_direction"]),
    ]) + build_shorts([
        ("M14L4_D4", "Why is it weak to explain summer by saying Earth is simply closer to the Sun then?", ["Because the seasons are mainly caused by axial tilt and changing sunlight angle, not by a simple distance change.", "Because Earth's tilted axis makes one hemisphere lean toward the Sun and get more direct sunlight, which is stronger than a distance explanation."], "Use tilt and sunlight-angle language.", ["season_distance_confusion"], ["season_reasoning"], acceptance_groups(["tilt", "axial tilt"], ["sunlight angle", "more direct sunlight", "leans toward"], ["not", "rather than"], ["distance", "closer to the Sun"])),
        ("M14L4_D10", "Why do opposite hemispheres not get the same season at the same time?", ["Because when one hemisphere tilts toward the Sun, the other tilts away and gets a different sunlight pattern.", "Because the same tilted axis favors one hemisphere while disfavoring the other."], "Use opposite-hemisphere language.", ["hemisphere_season_confusion"], ["hemisphere_compare"], acceptance_groups(["one hemisphere"], ["toward the Sun", "leans toward"], ["other hemisphere"], ["away", "leans away"], ["different seasons", "opposite seasons"])),
    ])
    concept = build_mcqs([
        ("M14L4_C1", "If Earth had no axial tilt, the best simple prediction is that...", ["the usual seasonal contrast would be much weaker", "Earth would stop orbiting", "day and night would vanish", "the Moon would stop having phases"], 0, "Tilt is the main cause of the yearly seasonal contrast.", ["season_distance_confusion"], ["season_reasoning"]),
        ("M14L4_C2", "About six months after December in the Northern Hemisphere, the season is most likely...", ["summer", "winter again", "always autumn", "nighttime"], 0, "Half a year later the geometry reverses.", ["hemisphere_season_confusion"], ["hemisphere_compare"]),
        ("M14L4_C4", "If it is December and the Northern Hemisphere tilts away from the Sun, which hemisphere tilts more toward the Sun?", ["Southern Hemisphere", "Northern Hemisphere", "both equally", "neither"], 0, "Opposite hemispheres trade the favored position.", ["hemisphere_season_confusion"], ["hemisphere_compare"]),
        ("M14L4_C5", "Which quantity is closest to Earth's axial tilt in this lesson?", ["23.4 degrees", "2.34 degrees", "45 degrees", "90 degrees"], 0, "Keep the 23.4-degree tilt visible.", ["tilt_direction_confusion"], ["tilt_value"]),
        ("M14L4_C6", "Which statement best keeps the geometry straight?", ["The same tilted axis direction in space leads to opposite seasonal lean at opposite sides of the orbit.", "Earth points a different random way each month.", "Summer begins whenever Earth is nearest the Sun.", "Tilt matters only at the equator."], 0, "The axis direction stays roughly fixed in space.", ["tilt_direction_confusion", "season_distance_confusion"], ["tilt_direction"]),
        ("M14L4_C7", "If the tilt were larger, the simple prediction would be...", ["a stronger seasonal contrast", "no seasons at all", "a shorter year", "a slower rotation"], 0, "A larger tilt would strengthen the seasonal contrast.", ["tilt_direction_confusion"], ["season_reasoning"]),
    ]) + build_shorts([
        ("M14L4_C3", "Why do opposite hemispheres get opposite seasons?", ["Because when one hemisphere tilts toward the Sun, the other tilts away from it.", "Because the same axial tilt makes one side lean toward the lantern while the other side leans away."], "Use toward-and-away language.", ["hemisphere_season_confusion"], ["hemisphere_compare"], acceptance_groups(["one hemisphere"], ["toward the Sun", "leans toward"], ["other hemisphere"], ["away from the Sun", "leans away"], ["opposite seasons", "different seasons"])),
        ("M14L4_C8", "Why is the fixed axis direction important in the seasons lesson?", ["Because the axis keeps roughly the same direction in space, so different parts of the orbit make different hemispheres lean toward the Sun.", "Because the same tilted axis lets the favored hemisphere switch as Earth moves around the Sun."], "Keep axis direction and orbit position together.", ["tilt_direction_confusion"], ["tilt_direction", "season_reasoning"], acceptance_groups(["axis", "tilt"], ["same direction", "fixed direction", "keeps the same direction"], ["orbit", "moves around the Sun"], ["hemisphere", "toward the Sun", "leans toward"])),
    ])
    mastery = build_mcqs([
        ("M14L4_M1", "If it is June and the Northern Hemisphere is tilted toward the Sun, the Southern Hemisphere is most likely experiencing...", ["winter", "summer", "noon", "full moon"], 0, "Opposite hemispheres have opposite seasons.", ["hemisphere_season_confusion"], ["hemisphere_compare"]),
        ("M14L4_M2", "Which statement best protects against the distance misconception?", ["Seasons are driven mainly by tilt and sunlight angle.", "Seasons happen because Earth stops rotating.", "Seasons are caused by the Moon's shadow.", "Seasons happen because the Sun moves around Earth."], 0, "Use tilt and sunlight angle language.", ["season_distance_confusion"], ["season_reasoning"]),
        ("M14L4_M3", "Earth's tilt is closest to...", ["23.4 degrees", "45 degrees", "75 degrees", "180 degrees"], 0, "Keep the tilt value visible.", ["tilt_direction_confusion"], ["tilt_value"]),
        ("M14L4_M5", "About how many months after June is the opposite seasonal geometry reached?", ["6 months", "1 month", "3 months", "9 months"], 0, "Opposite seasonal geometry is reached after about half a year.", ["hemisphere_season_confusion"], ["season_timing"]),
        ("M14L4_M6", "Which statement best explains why one hemisphere has longer summer days?", ["It leans toward the Sun and receives a more direct sunlight pattern for longer each day.", "It becomes much closer to the Sun than the other hemisphere.", "It rotates faster than the other hemisphere.", "The Moon adds extra daylight."], 0, "Use lean and sunlight-angle language.", ["season_distance_confusion"], ["season_reasoning"]),
        ("M14L4_M7", "If Earth's tilt were zero in the simple model, what would most likely happen to the usual seasons?", ["They would become much weaker", "They would become much stronger", "They would turn into Moon phases", "They would reverse every day"], 0, "Tilt creates the usual strong seasonal contrast.", ["season_distance_confusion"], ["season_reasoning"]),
        ("M14L4_M8", "Which statement is strongest?", ["The same tilted axis can favor one hemisphere in June and the other in December.", "The axis points toward the Sun only in summer and vanishes in winter.", "Both hemispheres lean toward the Sun equally all year.", "Seasons happen because the Moon blocks sunlight differently."], 0, "Use the fixed-axis comparison.", ["tilt_direction_confusion"], ["tilt_direction"]),
        ("M14L4_M9", "If the Northern Hemisphere is in winter, the Southern Hemisphere is most likely in...", ["summer", "winter", "no season at all", "first quarter"], 0, "Opposite hemispheres have opposite seasons.", ["hemisphere_season_confusion"], ["hemisphere_compare"]),
    ]) + build_shorts([
        ("M14L4_M4", "Summarize the cause of seasons in one strong sentence.", ["Seasons happen because Earth's tilted axis makes each hemisphere receive different sunlight angles and day lengths during the year.", "The seasonal cycle comes from axial tilt, which makes one hemisphere lean toward the Sun and later away from it."], "Keep tilt, sunlight angle, and the year together.", ["season_distance_confusion"], ["season_reasoning"], acceptance_groups(["seasons"], ["tilt", "tilted axis", "axial tilt"], ["sunlight angle", "more direct sunlight", "day length"], ["during the year", "yearly", "as Earth orbits"])),
        ("M14L4_M10", "Explain in one sentence why the distance-only explanation fails for seasons.", ["Because opposite hemispheres have opposite seasons at the same time, which is better explained by tilt and sunlight angle than by one simple Earth-Sun distance.", "Because the seasonal pattern follows which hemisphere leans toward the Sun, not a single close-far change."], "Use hemisphere comparison plus tilt.", ["season_distance_confusion"], ["season_reasoning", "hemisphere_compare"], acceptance_groups(["tilt", "leans toward", "sunlight angle"], ["not", "rather than"], ["distance"], ["opposite hemispheres", "different seasons", "same time"])),
    ])
    return lesson_spec(
        "M14_L4",
        "Season Switch",
        sim("m14_season_switch_lab", "Season switch lab", "Move a tilted Earth around the Sun while keeping the axis direction fixed so the seasonal geometry becomes visible.", ["Compare June and December positions.", "Switch between Northern and Southern Hemisphere views.", "Keep tilt and distance explanations separate."], ["Explain seasons through axial tilt.", "Compare opposite hemispheres correctly."], ["orbit_position", "axial_tilt", "hemisphere_view"], "Season reasoning through tilt and changing orbit position."),
        diagnostic,
        "Earth keeps spinning, but the season story adds a tilted rod. The same lean means one hemisphere points more toward the Great Lantern during one part of the year lap and the other hemisphere points more toward it half a year later.",
        "Commit to seasons as a tilt-and-sunlight-angle story rather than a distance-only story.",
        [prompt_block("What mainly causes seasons on Earth?", "Axial tilt."), prompt_block("Why are opposite hemispheres different?", "When one tilts toward the Sun, the other tilts away.")],
        [prompt_block("Keep the axis direction fixed and move Earth to the opposite side of the Sun.", "The favored hemisphere should switch."), prompt_block("Compare the hemisphere tilted toward the Sun with the hemisphere tilted away.", "Sunlight angle and day length should differ.")],
        ["Why is the fixed tilt direction so important in the season story?", "Why is distance from the Sun not the best main explanation for the seasons?"],
        "Set the tilt geometry firmly before the Moon-phase lesson introduces a second orbiting body.",
        concept,
        mastery,
        contract(
            concept_targets=["Explain seasons through axial tilt and changing sunlight angle.", "Compare opposite hemispheres correctly during June and December."],
            core_concepts=["Earth's seasons are caused mainly by axial tilt.", "One hemisphere tilts toward the Sun while the other tilts away.", "Opposite hemispheres therefore experience opposite seasons.", "The axis keeping roughly the same direction in space is central to the yearly pattern."],
            prerequisite_lessons=["M14_L3"],
            misconception_focus=["season_distance_confusion", "tilt_direction_confusion", "hemisphere_season_confusion"],
            formulas=[relation("axial tilt ~ 23.4 degrees", "Earth's tilt value used in the season model.", ["deg"], "Use as the lean of the spin rod.")],
            representations=[representation("words", "Explains seasons through axial tilt and sunlight angle."), representation("diagram", "Shows June and December Earth positions with the same tilted axis direction."), representation("formula", "Uses the approximate tilt value.")],
            analogy_map=lantern_ring_map("the learner compares how a tilted world changes sunlight angle during the year lap"),
            worked_examples=[worked("It is June and the Northern Hemisphere is tilted toward the Sun. What season is the Southern Hemisphere most likely experiencing?", ["Notice that the hemispheres tilt in opposite ways at the same moment.", "If the north is tilted toward the Sun, the south is tilted away.", "Infer the opposite season."], "Winter in the Southern Hemisphere", "Opposite hemispheres experience opposite seasonal geometry.", "This protects learners from applying the same season to both hemispheres at once."), worked("A learner says, 'Summer happens because Earth is closest to the Sun then.' How do you correct the explanation?", ["Keep the axis tilt visible.", "Compare sunlight angle rather than just distance.", "State the stronger tilt-based explanation."], "Summer is better explained by axial tilt and more direct sunlight.", "The tilted hemisphere gets more direct sunlight and longer days, which is stronger than a distance-only story.", "This is the central misconception shield for the seasons lesson."), worked("Earth is at the December side of the orbit in the simple lesson geometry. Roughly how many months later will the opposite seasonal geometry appear?", ["Use the idea that opposite positions on the orbit are about half a year apart.", "Take half of 12 months.", "State the interval."], "About 6 months later", "Moving to the opposite side of the orbit swaps which hemisphere leans toward the Sun.", "This gives the lesson one clear time-scale calculation alongside the conceptual tilt story.")],
            visual_assets=[visual("m14-l4-season-switch", "Season switch", "Show June and December positions with the same axis direction so the season geometry stays readable.", "The season-switch diagram makes the fixed tilted axis visible so the lesson does not collapse back into a distance-only story.", diagram_type="seasons_tilt", meta={"tilt_deg": 23.4})],
            animation_assets=[],
            simulation_contract=sim_contract("m14_l4_season_switch_sim", "season_switch", "Move the tilted world around the Sun until the seasonal switch between hemispheres feels inevitable.", "Start with Earth in a June-like position with the Northern Hemisphere leaning toward the Sun.", ["Move to the opposite side of the orbit.", "Switch the hemisphere label."], "Watch the same tilted axis favor one hemisphere and then the other as Earth moves around the Sun.", "Seasons come from axial tilt and changing sunlight angle, not from a simple distance change.", controls=[("orbit_position", "Year-lap position", "Moves Earth to different places around the Sun."), ("axial_tilt", "Tilt rod", "Sets the lean that creates the season contrast.")], readouts=[("Favored hemisphere", "Shows which hemisphere is tilted more toward the Sun."), ("Season check", "Labels the likely seasonal direction for the current hemisphere view.")]),
            reflection_prompts=["Explain why tilt is stronger than distance as the cause of seasons."],
            mastery_skills=["identify_tilt", "tilt_value", "season_reasoning", "hemisphere_compare", "season_distance_correction"],
            variation_plan={"diagnostic": "Fresh attempts rotate between tilt-value, hemisphere, and misconception questions.", "concept_gate": "Concept-gate retries alternate between June-December comparisons and no-tilt cases.", "mastery": "Mastery varies hemisphere switches, summary explanations, and tilt-value prompts before repeating an earlier season family."},
            scaffold_support=scaffold(
                "Keep seasons tied to axial tilt, hemisphere comparison, and sunlight angle.",
                "Ask which hemisphere leans toward the Sun, then infer the likely sunlight angle and season before you mention distance.",
                "What single idea best explains opposite seasons in opposite hemispheres?",
                "Do not let the close-far Earth-Sun story replace the tilt geometry.",
                "The Lantern-Ring season switch works like a tilted globe carrying one hemisphere into a better Sun-facing pose while the other leans away.",
                "Why is the opposite-hemisphere comparison such a strong misconception check?",
                [
                    extra_section("Tilt Value", "Earth's tilt is about 23.4 degrees, enough to create a strong yearly contrast without making the axis horizontal.", "Why is 23.4 degrees more useful than simply saying 'Earth leans'?"),
                    extra_section("Half-Year Swap", "About six months later the favored hemisphere reverses because Earth reaches the opposite side of its orbit.", "Which hemisphere is favored half a year after June?"),
                ],
            ),
            visual_clarity_checks=visual_checks("season switch"),
        ),
    )


def lesson_five() -> Dict[str, Any]:
    diagnostic = build_mcqs([
        ("M14L5_D1", "Moonlight is mainly...", ["reflected sunlight", "light made by the Moon itself", "Earth's shadow glowing", "a form of sound"], 0, "The Moon reflects sunlight.", ["moon_self_light_confusion"], ["moon_light_source"]),
        ("M14L5_D2", "At any moment the Moon is...", ["half lit by the Sun", "completely lit", "completely dark", "lit only during full moon"], 0, "The Sun always lights half of the Moon.", ["moon_phase_shadow_confusion"], ["phase_reasoning"]),
        ("M14L5_D3", "Ordinary Moon phases happen mainly because...", ["we see different amounts of the Moon's lit half", "Earth's shadow covers different pieces each week", "the Moon changes how much light it makes", "the Sun changes color"], 0, "Phase is a viewing-geometry story.", ["moon_phase_shadow_confusion"], ["phase_reasoning"]),
        ("M14L5_D5", "Which phase is strongest when the Moon is on the Sun side of Earth?", ["new moon", "full moon", "third quarter", "waning gibbous"], 0, "Near the Sun side gives a new moon view.", ["moon_phase_shadow_confusion"], ["phase_sequence"]),
        ("M14L5_D6", "Which phase is strongest when the Moon is opposite the Sun from Earth?", ["full moon", "new moon", "waxing crescent", "first quarter"], 0, "Opposite the Sun gives a full moon view.", ["moon_phase_shadow_confusion"], ["phase_sequence"]),
        ("M14L5_D7", "What does waxing mean in this lesson?", ["the visible lit part is growing", "the Moon is making its own light", "Earth's shadow is growing", "the orbit is getting faster"], 0, "Waxing means the visible lit part is increasing.", ["quarter_moon_name_confusion"], ["phase_sequence"]),
        ("M14L5_D8", "What does waning mean in this lesson?", ["the visible lit part is shrinking", "the Moon is disappearing permanently", "Earth's shadow is larger than the Moon", "the Sun is dimmer"], 0, "Waning means the visible lit part is decreasing.", ["quarter_moon_name_confusion"], ["phase_sequence"]),
        ("M14L5_D9", "About one week after new moon, the phase is closest to...", ["first quarter", "full moon", "new moon again", "waning crescent"], 0, "A week after new moon is roughly first quarter.", ["quarter_moon_name_confusion"], ["phase_timing"]),
    ]) + build_shorts([
        ("M14L5_D4", "Why is it weak to say ordinary Moon phases are caused by Earth's shadow?", ["Because ordinary phases come from our changing view of the Moon's sunlit half, while Earth's shadow matters only during a lunar eclipse.", "Because the Moon is always half lit by the Sun and the phase depends on viewing geometry, not on Earth's shadow covering it each week."], "Use lit-half and eclipse language.", ["moon_phase_shadow_confusion"], ["phase_shadow_correction"], acceptance_groups(["phases"], ["view", "see different amounts", "viewing geometry"], ["lit half", "sunlit half"], ["Earth's shadow"], ["eclipse"])),
        ("M14L5_D10", "Why does the Moon not need to make its own light to show phases?", ["Because the Sun lights half of the Moon and we just see different amounts of that lit half.", "Because phase changes come from reflected sunlight plus changing viewing geometry."], "Keep reflected light and changing view together.", ["moon_self_light_confusion"], ["moon_light_source", "phase_reasoning"], acceptance_groups(["Sun", "reflected sunlight", "lights"], ["half lit", "lit half"], ["see different amounts", "viewing geometry", "changing view"])),
    ])
    concept = build_mcqs([
        ("M14L5_C1", "What phase is most likely when the Moon appears mostly lit and is increasing in illumination?", ["waxing gibbous", "waning crescent", "new moon", "third quarter"], 0, "Waxing means increasing, and gibbous means more than half lit.", ["moon_phase_shadow_confusion"], ["phase_sequence"]),
        ("M14L5_C2", "What does 'first quarter' mainly refer to?", ["the Moon being about a quarter of the way around its orbit from new moon", "only a quarter of the Moon being lit", "Earth's shadow covering most of the Moon", "the Moon making only quarter brightness"], 0, "Quarter names the orbital position idea.", ["quarter_moon_name_confusion"], ["phase_sequence"]),
        ("M14L5_C4", "About one week after full moon, the phase is closest to...", ["third quarter", "new moon", "full moon again", "waxing crescent"], 0, "About a week after full is roughly third quarter.", ["quarter_moon_name_confusion"], ["phase_timing"]),
        ("M14L5_C5", "Which phase is strongest when the visible lit part is more than half and still increasing?", ["waxing gibbous", "waning crescent", "new moon", "third quarter"], 0, "More than half lit and increasing means waxing gibbous.", ["quarter_moon_name_confusion"], ["phase_sequence"]),
        ("M14L5_C6", "About how long is it from new moon to full moon in the simple monthly cycle?", ["about two weeks", "about one day", "about six months", "about one year"], 0, "New moon to full moon is about half a lunar cycle.", ["moon_phase_shadow_confusion"], ["phase_timing"]),
        ("M14L5_C7", "Which event actually uses Earth's shadow on the Moon?", ["lunar eclipse", "every full moon", "first quarter", "waxing crescent"], 0, "Earth's shadow is an eclipse idea.", ["moon_phase_shadow_confusion"], ["phase_shadow_correction"]),
    ]) + build_shorts([
        ("M14L5_C3", "Explain why the Moon is always half lit even though we do not always see a full moon.", ["Because the Sun always lights half of the Moon, but from Earth we see different fractions of that lit half as the Moon moves around us.", "Because the amount lit by the Sun stays half, while our viewing angle changes during the Moon's orbit."], "Keep Sun lighting and Earth viewing angle together.", ["moon_phase_shadow_confusion"], ["phase_reasoning"], acceptance_groups(["Sun", "lights", "half lit"], ["Earth", "we see", "viewing angle"], ["different amounts", "different fractions", "lit half"])),
        ("M14L5_C8", "Why does 'first quarter' not mean only a quarter of the Moon is lit?", ["Because quarter names the Moon's position in the cycle, while the Sun still lights half of the Moon.", "Because the Moon is still half lit; 'quarter' refers to where it is in the orbit sequence."], "Keep phase name and lit fraction separate.", ["quarter_moon_name_confusion"], ["phase_sequence"], acceptance_groups(["quarter", "phase cycle", "orbit"], ["half lit", "Sun lights half"], ["not", "rather than"], ["quarter of the Moon is lit", "only a quarter lit"])),
    ])
    mastery = build_mcqs([
        ("M14L5_M1", "About two weeks after new moon, the phase is closest to...", ["full moon", "new moon again", "third quarter", "waning crescent"], 0, "Full moon is about half a cycle after new moon.", ["moon_phase_shadow_confusion"], ["phase_timing"]),
        ("M14L5_M2", "Which event actually needs Earth's shadow to line up with the Moon?", ["lunar eclipse", "every ordinary phase", "waxing crescent", "first quarter"], 0, "Earth's shadow is an eclipse idea.", ["moon_phase_shadow_confusion"], ["phase_shadow_correction"]),
        ("M14L5_M3", "What changes during the ordinary monthly phase cycle?", ["our view of the Moon's lit half", "how much of the Moon the Sun lights", "the Moon's own light production", "Earth's orbit around the Sun"], 0, "The changing view is the central idea.", ["moon_phase_shadow_confusion"], ["phase_reasoning"]),
        ("M14L5_M5", "Which phase is strongest just after full moon when the visible lit part starts shrinking?", ["waning gibbous", "waxing crescent", "new moon", "first quarter"], 0, "After full and shrinking gives waning gibbous.", ["quarter_moon_name_confusion"], ["phase_sequence"]),
        ("M14L5_M6", "Which phase shows the least visible lit half from Earth?", ["new moon", "full moon", "waxing gibbous", "first quarter"], 0, "New moon gives the least visible lit part from Earth.", ["moon_phase_shadow_confusion"], ["phase_sequence"]),
        ("M14L5_M7", "About three weeks after new moon, the phase is closest to...", ["third quarter", "full moon", "new moon again", "waxing gibbous"], 0, "Three weeks after new moon is roughly third quarter.", ["quarter_moon_name_confusion"], ["phase_timing"]),
        ("M14L5_M8", "Which statement is strongest?", ["The Sun always lights half of the Moon, but Earth does not always see that half in the same way.", "The Moon makes more light at full moon than at new moon.", "Earth's shadow covers the Moon a little every week.", "The Moon is dark except during eclipses."], 0, "Keep constant lighting and changing view together.", ["moon_phase_shadow_confusion", "moon_self_light_confusion"], ["phase_reasoning"]),
        ("M14L5_M9", "What word best describes a phase sequence in which the visible lit portion is decreasing?", ["waning", "waxing", "full", "new"], 0, "Decreasing visible illumination is waning.", ["quarter_moon_name_confusion"], ["phase_sequence"]),
    ]) + build_shorts([
        ("M14L5_M4", "Summarize Moon phases in one strong sentence.", ["Moon phases happen because we see different amounts of the Moon's sunlit half as it orbits Earth.", "The Moon is always half lit by the Sun, and the changing phase is our changing view of that lit half."], "Keep orbit and changing view together.", ["moon_phase_shadow_confusion"], ["phase_reasoning"], acceptance_groups(["Moon phases"], ["see different amounts", "changing view"], ["sunlit half", "lit half", "half lit"], ["orbits Earth", "moves around Earth"])),
        ("M14L5_M10", "Explain in one sentence why Earth's shadow is not the monthly cause of normal phases.", ["Because the normal monthly phase cycle comes from our changing view of the Moon's lit half, while Earth's shadow lines up only during a lunar eclipse.", "Because phases happen every month from viewing geometry, but Earth's shadow matters only in eclipse events."], "Use ordinary-phases versus eclipse language.", ["moon_phase_shadow_confusion"], ["phase_shadow_correction"], acceptance_groups(["phases", "monthly"], ["view", "changing view", "viewing geometry"], ["lit half", "sunlit half"], ["Earth's shadow"], ["eclipse"])),
    ])
    return lesson_spec(
        "M14_L5",
        "Moon Face Challenge",
        sim("m14_moon_face_challenge_lab", "Moon face challenge", "Move the Moon around Earth under one fixed lantern so the phase cycle becomes a geometry story instead of a shadow myth.", ["Place the Moon at new, quarter, and full positions.", "Track whether the visible lit part is waxing or waning.", "Separate normal phases from eclipse situations."], ["Explain ordinary Moon phases through viewing geometry.", "Describe the Moon as reflecting sunlight."], ["moon_position", "phase_name", "visible_fraction"], "Moon phase reasoning through Sun-Earth-Moon geometry."),
        diagnostic,
        "The companion rider does not make its own light. The Great Lantern always lights half of it. As the companion moves around the home world, we see different portions of that lit half. That is why phases are a viewing story, not a shadow story.",
        "Commit to Moon phases as a changing-view geometry story rather than an Earth-shadow story.",
        [prompt_block("What lights the Moon?", "Reflected sunlight from the Sun."), prompt_block("What changes during the phase cycle?", "Our view of the Moon's lit half.")],
        [prompt_block("Place the Moon near the Sun side of Earth.", "That gives a new moon view."), prompt_block("Move the Moon to the opposite side of Earth.", "That gives a full moon view.")],
        ["Why is 'always half lit' compatible with the changing phase cycle?", "Why does Earth's shadow belong to eclipse explanations rather than ordinary phases?"],
        "Keep the Moon's lighting simple before the final year-lap lesson compares orbital periods.",
        concept,
        mastery,
        contract(
            concept_targets=["Explain Moon phases through changing viewing geometry.", "Describe the Moon as reflecting sunlight rather than making its own light."],
            core_concepts=["The Moon is always half lit by the Sun.", "Phases come from our changing view of that lit half as the Moon orbits Earth.", "Earth's shadow matters during a lunar eclipse, not during the ordinary phase cycle.", "Waxing means the visible lit part is growing, while waning means it is shrinking."],
            prerequisite_lessons=["M14_L3", "M14_L4"],
            misconception_focus=["moon_phase_shadow_confusion", "moon_self_light_confusion", "quarter_moon_name_confusion"],
            formulas=[relation("new -> first quarter -> full -> third quarter -> new", "Simplified phase sequence around one lunar cycle.", ["sequence"], "Use for the order of common named phases.")],
            representations=[representation("words", "Explains phases as a changing view of the Moon's sunlit half."), representation("diagram", "Shows the Sun, Earth, Moon positions, and named phase view."), representation("formula", "Uses a simple phase sequence.")],
            analogy_map=lantern_ring_map("the learner predicts how the companion rider's lit half looks from Earth at different orbital positions"),
            worked_examples=[worked("The Moon is on the opposite side of Earth from the Sun. What phase is most likely?", ["Notice that the Moon's sunlit half faces Earth in this geometry.", "Use the opposite-side clue.", "Name the phase."], "Full moon", "When the Moon is opposite the Sun, we see most of its lit half.", "This gives learners a strong geometry anchor for the full moon without using shadow language."), worked("A learner says, 'First quarter means only a quarter of the Moon is lit.' How do you correct that?", ["Notice that the Sun still lights half of the Moon.", "Remember that quarter names the orbital position in the cycle.", "State what we usually see at first quarter."], "First quarter means the Moon is about a quarter of the way around its orbit, while we see about half of the lit half.", "The name is about the phase cycle position, not a quarter-lit Moon.", "This protects against a persistent Moon-phase naming confusion."), worked("It is new moon. About how long is it until full moon in the simple cycle?", ["Use the phase sequence from new to full.", "Notice that full moon is about half a cycle later.", "State the approximate time."], "About two weeks", "A full moon is roughly halfway through the monthly phase cycle after new moon.", "This gives the lesson a timing anchor in addition to the geometry language.")],
            visual_assets=[visual("m14-l5-moon-face-challenge", "Moon face challenge", "Show Earth, Moon, the Sun, and one named Moon position so the visible phase is read from geometry rather than shadow.", "The companion-face diagram keeps the Moon always half lit and lets the viewing angle do the explanatory work.", diagram_type="moon_phases", meta={"moon_position": 2})],
            animation_assets=[],
            simulation_contract=sim_contract("m14_l5_moon_face_sim", "moon_face_challenge", "Move the companion rider until the current phase can be predicted from geometry alone.", "Start with Earth and Moon under one fixed Great Lantern.", ["Place the Moon at new, quarter, and full positions.", "Switch between waxing and waning positions."], "Watch the visible lit fraction change because your viewpoint changes while the Sun still lights half the Moon.", "Moon phases are a Sun-Earth-Moon viewing story, not an Earth-shadow story.", controls=[("moon_position", "Moon position", "Moves the companion rider around Earth."), ("phase_name", "Phase label", "Checks whether the learner links geometry to the correct phase word.")], readouts=[("Current phase", "Names the phase suggested by the current Moon position."), ("Light source", "Reminds the learner that the Sun lights the Moon.")]),
            reflection_prompts=["Explain why Moon phases are stronger as a viewing story than as a shadow story."],
            mastery_skills=["moon_light_source", "phase_reasoning", "phase_sequence", "phase_shadow_correction", "moon_geometry_view"],
            variation_plan={"diagnostic": "Fresh attempts rotate between light-source, geometry, and misconception prompts.", "concept_gate": "Concept-gate retries alternate between new-full-quarter geometry and waxing-waning language.", "mastery": "Mastery varies sequence, timing, summary, and misconception-correction tasks before repeating an earlier Moon-phase family."},
            scaffold_support=scaffold(
                "Keep Moon phases tied to the Sun-lit half and Earth's changing viewpoint.",
                "Ask first what the Sun is lighting, then ask what Earth can see of that lit half from the current geometry.",
                "What stays constant in the phase cycle even while the visible phase name changes?",
                "Do not let Earth's shadow replace the normal phase explanation.",
                "The Lantern-Ring companion-face story works because one lit half can look different from different viewing positions around the orbit.",
                "Why can the Moon stay half lit even when we see only a thin crescent?",
                [
                    extra_section("Light Source", "The Moon reflects sunlight rather than making its own light.", "Why would the phase story collapse if the Moon were treated as its own light source?"),
                    extra_section("Naming Trap", "Quarter names the cycle position, not a literal quarter-lit Moon.", "What does 'first quarter' track more strongly: lit fraction or orbital position?"),
                ],
            ),
            visual_clarity_checks=visual_checks("Moon phase board"),
        ),
    )


def lesson_six() -> Dict[str, Any]:
    diagnostic = build_mcqs([
        ("M14L6_D1", "In the Lantern-Ring model, a year lap stands for...", ["orbital period", "rotation axis", "day-night line", "Moon phase"], 0, "A year lap is the orbital period.", ["outer_orbit_same_period_confusion"], ["identify_orbital_period"]),
        ("M14L6_D2", "Ring reach stands for...", ["orbital distance", "gravity strength only", "day length", "phase size"], 0, "Ring reach is orbital distance.", ["orbital_distance_period_confusion"], ["identify_orbital_distance"]),
        ("M14L6_D3", "Which world usually has the longer year lap?", ["the one on the farther ring", "the one closer to the Sun", "both always the same", "the one spinning faster"], 0, "Farther worlds usually take longer to complete an orbit.", ["outer_orbit_same_period_confusion"], ["distance_period_reasoning"]),
        ("M14L6_D5", "If an inner world completes 2 laps while an outer world completes 1 in the same interval, which has the longer orbital period?", ["the outer world", "the inner world", "both the same", "cannot be decided"], 0, "Fewer laps in the same time means a longer period.", ["outer_orbit_same_period_confusion"], ["compare_orbital_periods"]),
        ("M14L6_D6", "Which change usually lengthens a world's year lap in this module?", ["moving it to a farther ring", "making its day shorter", "changing Moon phase", "tilting its axis"], 0, "Farther ring reach usually means a longer year.", ["orbital_distance_period_confusion"], ["distance_period_reasoning"]),
        ("M14L6_D7", "Which statement is strongest?", ["Year length and day length are different measurements.", "A longer day automatically means a longer year.", "Every planet's year is about one Earth year.", "Moon phase sets the year length."], 0, "Rotation period and orbital period must stay separate.", ["rotation_orbit_confusion"], ["year_lap_compare"]),
        ("M14L6_D8", "If two worlds are compared over the same time interval and one completes more laps, that world has the...", ["shorter orbital period", "longer orbital period", "same orbital period", "greater axial tilt"], 0, "More laps in the same time means a shorter period.", ["outer_orbit_same_period_confusion"], ["compare_orbital_periods"]),
        ("M14L6_D9", "Which term should be compared if you want to know which planet takes longer to go around the Sun?", ["orbital period", "rotation axis", "phase", "sunlight angle"], 0, "Year length is orbital period.", ["outer_orbit_same_period_confusion"], ["identify_orbital_period"]),
    ]) + build_shorts([
        ("M14L6_D4", "Why does a farther ring usually mean a longer year lap in this module?", ["Because a world on a farther orbit usually takes longer to travel around the Sun once.", "Because greater ring reach is linked qualitatively to a longer orbital period."], "Use farther-orbit and longer-time language.", ["orbital_distance_period_confusion"], ["distance_period_reasoning"], acceptance_groups(["farther orbit", "greater ring reach", "farther ring"], ["longer", "takes longer"], ["around the Sun", "one orbit", "orbital period"])),
        ("M14L6_D10", "Why is it weak to say all planets should take about one year because they all orbit the Sun?", ["Because different planets orbit at different distances, so their orbital periods can be very different.", "Because sharing the same Sun does not force all year laps to match."], "Use common-host but different-distance language.", ["outer_orbit_same_period_confusion"], ["distance_period_reasoning"], acceptance_groups(["different distances", "farther ring", "orbital distance"], ["different periods", "different years", "longer or shorter"], ["same Sun", "orbit the Sun"])),
    ])
    concept = build_mcqs([
        ("M14L6_C1", "If an inner world completes 4 laps while an outer world completes 1 in the same interval, which has the shorter orbital period?", ["the inner world", "the outer world", "both the same", "cannot be decided"], 0, "More laps in the same time means a shorter orbital period.", ["outer_orbit_same_period_confusion"], ["compare_orbital_periods"]),
        ("M14L6_C2", "Which term best names the time for one full orbit?", ["orbital period", "axial tilt", "new moon", "rotation axis"], 0, "That time is the orbital period.", ["outer_orbit_same_period_confusion"], ["identify_orbital_period"]),
        ("M14L6_C4", "If a world has a longer year than Earth in this lesson, it is most likely on a...", ["farther ring", "closer ring", "ring of exactly the same size", "day-night boundary"], 0, "Longer year usually goes with farther orbit.", ["orbital_distance_period_confusion"], ["distance_period_reasoning"]),
        ("M14L6_C5", "Which comparison best reveals orbital period from a shared time interval?", ["number of laps completed", "tilt angle", "Moon phase name", "planet color"], 0, "Lap count in the same interval reveals which period is shorter or longer.", ["outer_orbit_same_period_confusion"], ["compare_orbital_periods"]),
        ("M14L6_C6", "Which statement best protects against the 'same Sun, same year' idea?", ["Different orbital distances can produce very different orbital periods.", "All Sun-orbiting worlds take about one year.", "Only Earth has an orbital period.", "A longer year means a darker planet."], 0, "Distance and period are linked, so the years need not match.", ["outer_orbit_same_period_confusion"], ["distance_period_reasoning"]),
        ("M14L6_C7", "If an outer world completes fewer laps than an inner world in the same time, the outer world's year is...", ["longer", "shorter", "the same", "impossible to compare"], 0, "Fewer laps in the same interval means a longer period.", ["outer_orbit_same_period_confusion"], ["compare_orbital_periods"]),
    ]) + build_shorts([
        ("M14L6_C3", "Explain the qualitative distance-period rule in one sentence.", ["Worlds on farther rings usually take longer to complete one orbit around the Sun.", "Greater orbital distance usually goes with a longer orbital period."], "Use farther-distance and longer-period language.", ["orbital_distance_period_confusion"], ["distance_period_reasoning"], acceptance_groups(["farther", "greater orbital distance", "farther ring"], ["longer", "takes longer"], ["orbit", "orbital period", "year"])),
        ("M14L6_C8", "Why does counting laps in the same time window help you compare years?", ["Because the world that completes more laps in the same interval must have the shorter orbital period.", "Because shared time makes lap count a direct clue to which year is shorter or longer."], "Use same-time-window language.", ["outer_orbit_same_period_confusion"], ["compare_orbital_periods"], acceptance_groups(["same time", "same interval", "same window"], ["more laps", "fewer laps"], ["shorter period", "longer period", "year"])),
    ])
    mastery = build_mcqs([
        ("M14L6_M1", "A planet on a farther ring than Earth is most likely to have a year that is...", ["longer than Earth's", "shorter than Earth's", "exactly the same", "equal to one day"], 0, "Farther ring reach usually means longer year lap.", ["outer_orbit_same_period_confusion"], ["compare_orbital_periods"]),
        ("M14L6_M2", "Which statement best protects against 'all planets take about a year'?", ["Year length depends on orbital distance, so different worlds can have very different orbital periods.", "All worlds take about one Earth year.", "Only Earth really has a year.", "Year length is set by Moon phases."], 0, "Different ring reach means different year length.", ["outer_orbit_same_period_confusion"], ["distance_period_reasoning"]),
        ("M14L6_M3", "Which quantity should you compare if you want to know which planet takes longer to go around the Sun?", ["orbital period", "rotation rate", "phase", "shadow length"], 0, "Year length is orbital period.", ["outer_orbit_same_period_confusion"], ["identify_orbital_period"]),
        ("M14L6_M5", "If a planet has a shorter year than Earth, it is most likely on a ring that is...", ["closer to the Sun", "farther from the Sun", "exactly Earth-sized", "tilted more"], 0, "A shorter year usually goes with a closer orbit.", ["orbital_distance_period_confusion"], ["distance_period_reasoning"]),
        ("M14L6_M6", "Which comparison is strongest if you want to estimate year length from a picture of the Solar System?", ["orbital distance from the Sun", "Moon phase", "color of the planet", "day length only"], 0, "Distance is the key comparison for the qualitative year rule here.", ["orbital_distance_period_confusion"], ["identify_orbital_distance"]),
        ("M14L6_M7", "An inner world completes 4 laps while an outer world completes 1 in the same interval. About how many times longer is the outer world's period?", ["4 times", "2 times", "1/4 as long", "cannot be compared"], 0, "If one completes 1 lap while the other completes 4 in the same interval, the single-lap world has about four times the period.", ["outer_orbit_same_period_confusion"], ["compare_orbital_periods"]),
        ("M14L6_M8", "Which statement is strongest?", ["Different orbital distances around the same Sun can still give very different year lengths.", "Sharing the same Sun forces every year to be the same.", "A longer year means a brighter planet.", "Rotation period decides the orbital period."], 0, "The common host does not force equal years.", ["outer_orbit_same_period_confusion"], ["distance_period_reasoning"]),
        ("M14L6_M9", "Which quantity must stay separate from year length in this lesson?", ["day length from rotation", "orbital distance", "lap count", "inner versus outer ring"], 0, "Day length belongs to rotation, not to orbital period.", ["rotation_orbit_confusion"], ["year_lap_compare"]),
    ]) + build_shorts([
        ("M14L6_M4", "Summarize the outer-lap idea in one strong sentence.", ["Farther worlds usually take longer to complete one orbit around the Sun, so their years are usually longer.", "Greater ring reach usually means a longer year lap around the Great Lantern."], "Keep distance and period together.", ["orbital_distance_period_confusion"], ["distance_period_reasoning"], acceptance_groups(["farther", "greater ring reach", "outer"], ["longer", "takes longer"], ["orbit", "orbital period", "year"])),
        ("M14L6_M10", "Explain in one sentence why sharing the same Sun does not force all planets to have the same year length.", ["Because orbital distance still differs from planet to planet, and that changes the orbital period.", "Because the same central Sun can host worlds on very different ring reaches and therefore different year laps."], "Use same-Sun and different-distance language together.", ["outer_orbit_same_period_confusion"], ["distance_period_reasoning"], acceptance_groups(["same Sun", "same central Sun"], ["different distances", "different ring reaches", "orbital distance"], ["different years", "orbital periods", "longer or shorter"])),
    ])
    return lesson_spec(
        "M14_L6",
        "Outer Lap Puzzle",
        sim("m14_outer_lap_puzzle_lab", "Outer lap puzzle", "Compare inner and outer solar rings so orbital distance and year length stay tied together in one visual pattern.", ["Compare inner and outer worlds starting at the same position.", "Count how many laps each completes in the same time.", "Describe the pattern qualitatively before naming Kepler."], ["Explain why farther worlds usually have longer orbital periods.", "Compare year length without confusing it with day length."], ["inner_distance", "outer_distance", "lap_count"], "Qualitative orbital-period comparison."),
        diagnostic,
        "Inner ring routes are shorter and usually give shorter year laps. Outer ring routes are farther from the Great Lantern and usually take longer to complete. The key idea is the pattern linking ring reach and year lap.",
        "Commit to year length as an orbit-distance story rather than assuming all worlds take roughly the same time.",
        [prompt_block("What does a year lap stand for?", "One full orbit around the Sun."), prompt_block("What does ring reach stand for?", "Orbital distance from the Sun.")],
        [prompt_block("Compare an inner world with an outer world in the same time window.", "The inner world should finish more laps."), prompt_block("Keep day length separate from year length.", "Rotation and orbit are different comparisons.")],
        ["Why is a farther ring usually linked to a longer year?", "Why is it weak to assume every planet should take about one year?"],
        "Finish the module with a broad comparison rule that connects Solar Court geometry to a real orbital pattern.",
        concept,
        mastery,
        contract(
            concept_targets=["Explain that farther solar orbits usually have longer orbital periods.", "Distinguish orbital period from rotation period."],
            core_concepts=["A year lap is one full orbit around the Sun.", "Ring reach stands for orbital distance.", "Farther worlds usually take longer to complete one orbit.", "Inner worlds can complete more laps than outer worlds in the same time."],
            prerequisite_lessons=["M14_L2"],
            misconception_focus=["outer_orbit_same_period_confusion", "orbital_distance_period_confusion", "rotation_orbit_confusion"],
            formulas=[relation("greater orbital distance -> longer orbital period", "Qualitative distance-period rule for the lesson.", ["concept only"], "Use as the simple year-lap pattern.")],
            representations=[representation("words", "Describes how inner and outer worlds differ in year length."), representation("diagram", "Shows inner and outer rings with shorter and longer year laps."), representation("formula", "Uses the qualitative distance-period rule.")],
            analogy_map=lantern_ring_map("the learner compares inner and outer ring reaches to explain why year lengths differ"),
            worked_examples=[worked("An outer world and an inner world are watched for the same amount of time. The inner world completes 3 laps while the outer world completes 1. Which has the shorter orbital period?", ["Count the laps in the same time interval.", "Notice that more completed laps means each lap takes less time.", "State which world has the shorter year."], "The inner world has the shorter orbital period.", "Completing more laps in the same time means each orbit is shorter.", "This helps learners compare orbital periods without needing a memorized planet table."), worked("A learner says, 'All planets should take about a year because they all go around the Sun.' How do you correct that?", ["Compare ring reach first.", "Note that different orbital distances mean different year laps.", "State the qualitative rule."], "Different planets can have very different years because farther orbits usually take longer.", "The shared host is the Sun, but the orbital distances are not the same, so the periods are not the same either.", "This closes the module with a general pattern instead of a single-Earth assumption."), worked("An inner world completes 4 laps while an outer world completes 1 in the same time interval. About how many times longer is the outer world's year?", ["Use the shared time interval as the comparison frame.", "Notice that one world completes only one orbit while the other completes four.", "State the period ratio."], "About 4 times longer", "Completing one lap while another completes four in the same time means the one-lap world has about four times the period.", "This adds a clean quantitative comparison to the qualitative outer-lap rule.")],
            visual_assets=[visual("m14-l6-outer-lap-puzzle", "Outer lap puzzle", "Show inner and outer rings with shorter and longer year-lap arrows so the distance-period pattern stays visual.", "The outer-lap comparison makes year length a ring-distance pattern instead of a planet list to memorize.", diagram_type="orbit_distance_period")],
            animation_assets=[],
            simulation_contract=sim_contract("m14_l6_outer_lap_sim", "outer_lap_puzzle", "Compare inner and outer rings until longer years and farther distances feel like one connected pattern.", "Start with one inner world and one outer world at the same side of the Sun.", ["Count completed laps after one shared time interval.", "Move the outer world farther away."], "Watch the inner world complete more laps in the same interval while the outer world takes longer for one full orbit.", "Farther solar rings usually go with longer year laps.", controls=[("inner_distance", "Inner ring reach", "Sets how close the inner world is to the Sun."), ("outer_distance", "Outer ring reach", "Sets how far the outer world is from the Sun.")], readouts=[("Inner year", "Summarizes the inner world's orbital period qualitatively."), ("Outer year", "Summarizes the outer world's orbital period qualitatively.")]),
            reflection_prompts=["Explain why a farther ring usually means a longer year lap."],
            mastery_skills=["identify_orbital_period", "identify_orbital_distance", "distance_period_reasoning", "compare_orbital_periods", "year_lap_compare"],
            variation_plan={"diagnostic": "Fresh attempts rotate between year-lap, ring-reach, and inner-versus-outer comparisons.", "concept_gate": "Concept-gate retries alternate between orbit-distance reasoning and lap-count comparisons.", "mastery": "Mastery varies summary, comparison, and misconception-correction tasks before repeating an earlier orbital-period family."},
            scaffold_support=scaffold(
                "Keep year length tied to orbital distance and full-lap time, not to rotation.",
                "Ask first which world is farther from the Sun, then compare how many full laps each completes in the same time window.",
                "Which quantity best names one full trip around the Sun?",
                "Do not let day length or Moon phase replace orbital period.",
                "The Lantern-Ring outer-lap puzzle works because a larger ring route usually means a longer path and a longer year lap.",
                "Why is a shared time window such a strong way to compare years?",
                [
                    extra_section("Lap Counting", "Counting laps in the same interval turns orbital period into something visible instead of a memorized fact.", "If one world completes more laps in the same time, what does that mean for its period?"),
                    extra_section("Distance Rule", "Inner and outer rings give a qualitative version of the distance-period rule before Kepler is named formally.", "Why does farther ring reach usually mean a longer year?"),
                ],
            ),
            visual_clarity_checks=visual_checks("outer-lap board"),
        ),
    )


M14_SPEC = {
    "authoring_standard": AUTHORING_STANDARD_V3,
    "module_description": "Solar System structure, gravity-shaped orbits, day and night, seasons, Moon phases, and qualitative orbital-period comparisons taught through the Lantern-Ring Model so the Sun, planets, moons, tilt, and phases stay inside one coherent lit-and-pulled world.",
    "mastery_outcomes": [
        "Describe the Solar System as one Sun-centered family containing planets, dwarf planets, moons, asteroids, and comets.",
        "Explain orbits as gravity-shaped motion around the Sun or around planets.",
        "Explain day and night through rotation.",
        "Explain seasons through axial tilt rather than distance from the Sun.",
        "Explain Moon phases through changing viewing geometry of the Moon's lit half.",
        "Interpret qualitatively why farther solar orbits usually correspond to longer orbital periods.",
    ],
    "lessons": [lesson_one(), lesson_two(), lesson_three(), lesson_four(), lesson_five(), lesson_six()],
}


RELEASE_CHECKS = [
    "Every lesson keeps the Lantern-Ring language of Great Lantern, world riders, companion riders, hub pull, spin rods, tilt rods, and year laps coherent.",
    "Every explorer uses lesson-specific controls and readouts instead of the generic simulation fallback.",
    "Every worked example includes answer reasoning instead of only a final label or value.",
    "Every M14 visual keeps orbit geometry, tilt, lit halves, phase views, and distance-period comparisons readable without clipping or overlap.",
]


M14_MODULE_DOC, M14_LESSONS, M14_SIM_LABS = build_nextgen_module_bundle(
    module_id=M14_MODULE_ID,
    module_title=M14_MODULE_TITLE,
    module_spec=M14_SPEC,
    allowlist=M14_ALLOWLIST,
    content_version=M14_CONTENT_VERSION,
    release_checks=RELEASE_CHECKS,
    sequence=18,
    level="Module 14",
    estimated_minutes=320,
    authoring_standard=AUTHORING_STANDARD_V3,
    plan_assets=True,
    public_base="/lesson_assets",
)


def _sync_assessed_skills(lesson_pairs: Sequence[Tuple[str, Dict[str, Any]]]) -> None:
    for _, lesson in lesson_pairs:
        contract = lesson.get("authoring_contract") or {}
        declared: List[str] = []
        for skill in contract.get("mastery_skills") or []:
            cleaned = str(skill).strip()
            if cleaned and cleaned not in declared:
                declared.append(cleaned)
        concept_items: List[Dict[str, Any]] = []
        for capsule in lesson.get("phases", {}).get("concept_reconstruction", {}).get("capsules", []):
            concept_items.extend(capsule.get("checks") or [])
        mastery_items = lesson.get("phases", {}).get("transfer", {}).get("items") or []
        for item in [*concept_items, *mastery_items]:
            for skill in item.get("skill_tags") or []:
                cleaned = str(skill).strip()
                if cleaned and cleaned not in declared:
                    declared.append(cleaned)
        contract["mastery_skills"] = declared


_sync_assessed_skills(M14_LESSONS)


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed Module M14 into Firestore")
    parser.add_argument("--project", default=None)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--compile-assets", action="store_true")
    parser.add_argument("--asset-root", default="")
    parser.add_argument("--public-base", default="/lesson_assets")
    args = parser.parse_args()

    project = get_project_id(args.project)
    init_firebase(project)
    asset_root = args.asset_root or default_asset_root()
    module_doc = deepcopy(M14_MODULE_DOC)
    lesson_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in M14_LESSONS]
    sim_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in M14_SIM_LABS]

    if args.compile_assets:
        render_module_assets(lesson_pairs, sim_pairs, asset_root=asset_root, public_base=args.public_base)

    print_preview(module_doc, lesson_pairs, sim_pairs)
    db = init_firebase(project)
    plan: List[Tuple[str, str]] = [("modules", M14_MODULE_ID)]
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

