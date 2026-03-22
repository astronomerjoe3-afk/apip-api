from __future__ import annotations

import argparse
from copy import deepcopy
from typing import Any, Dict, List, Sequence, Tuple

try:
    from scripts.lesson_authoring_contract import AUTHORING_STANDARD_V1
    from scripts.module_asset_pipeline import default_asset_root, render_module_assets
    from scripts.nextgen_module_builder import build_nextgen_module_bundle
except ModuleNotFoundError:
    from lesson_authoring_contract import AUTHORING_STANDARD_V1
    from module_asset_pipeline import default_asset_root, render_module_assets
    from nextgen_module_builder import build_nextgen_module_bundle

try:
    from scripts.seed_m1_module import get_project_id, init_firebase, print_preview, upsert_doc
except ModuleNotFoundError:
    from seed_m1_module import get_project_id, init_firebase, print_preview, upsert_doc


M14_MODULE_ID = "M14"
M14_CONTENT_VERSION = "20260322_m14_lantern_ring_v1"
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
    if assessment_bank_targets:
        payload["assessment_bank_targets"] = deepcopy(assessment_bank_targets)
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
    ]) + build_shorts([
        ("M14L1_D4", "Why is the Solar System stronger as one Sun-centered family than as a random object list?", ["Because the Sun is the central star and its gravity organizes planets, moons, asteroids, comets, and dwarf planets into one system.", "Because one central Sun and its gravity tie the different body types into one family."], "Use center-and-gravity language.", ["sun_planet_confusion"], ["solar_family"], acceptance_groups(["Sun", "central"], ["gravity", "pull"], ["family", "system"], ["planets", "moons", "asteroids", "comets", "dwarf planets"])),
    ])
    concept = build_mcqs([
        ("M14L1_C1", "Which pair both orbit the Sun directly?", ["planet and dwarf planet", "moon and planet", "moon and moon", "moon and asteroid"], 0, "Planets and dwarf planets both orbit the Sun.", ["planet_category_confusion", "moon_planet_confusion"], ["solar_family"]),
        ("M14L1_C2", "Which statement best distinguishes a comet from an asteroid?", ["Comets are icy visitors, while asteroids are mainly rocky small bodies.", "Comets are always planets.", "Asteroids make their own light.", "Comets orbit Earth as companions."], 0, "The key contrast is icy versus mainly rocky.", ["comet_asteroid_confusion"], ["classify_small_bodies"]),
    ]) + build_shorts([
        ("M14L1_C3", "Why is a moon not the same category as a planet?", ["Because a moon mainly orbits a planet or dwarf planet, while a planet orbits the Sun directly.", "Because moons are companion riders around larger worlds, not world riders around the Sun."], "Contrast what each one mainly orbits.", ["moon_planet_confusion"], ["classify_moon", "classify_planet"], acceptance_groups(["moon", "companion"], ["orbits"], ["planet", "larger world"], ["planet"], ["Sun", "directly"])),
    ])
    mastery = build_mcqs([
        ("M14L1_M1", "Which body is the main light source in the Solar System?", ["Sun", "Moon", "Jupiter", "comet"], 0, "The Sun is the Great Lantern.", ["sun_planet_confusion"], ["identify_sun"]),
        ("M14L1_M2", "Which body is most likely an ice visitor?", ["comet", "Mercury", "Moon", "Sun"], 0, "Ice visitors are comets.", ["comet_asteroid_confusion"], ["classify_small_bodies"]),
        ("M14L1_M3", "Which statement is strongest?", ["Not everything orbiting the Sun is a planet.", "Everything orbiting the Sun is a planet.", "Moons orbit the Sun the same way planets do.", "The Sun is a companion rider."], 0, "The Solar System contains several object categories.", ["planet_category_confusion"], ["solar_family"]),
    ]) + build_shorts([
        ("M14L1_M4", "Summarize the Solar System in one strong Lantern-Ring sentence.", ["The Solar System is one Sun-centered family in which planets, dwarf planets, moons, asteroids, and comets move under the Sun's gravity.", "One Great Lantern sits at the center while many different riders move around it under hub pull."], "Keep the Sun-centered family and gravity together.", ["sun_planet_confusion"], ["solar_family"], acceptance_groups(["Sun", "Great Lantern", "center"], ["family", "system"], ["gravity", "hub pull"], ["planets", "moons", "asteroids", "comets", "dwarf planets"])),
    ])
    return lesson_spec(
        "M14_L1",
        "Build the Solar Court",
        sim("m14_solar_court_sort_lab", "Solar court sorter", "Sort Solar System bodies so the Sun-centered family becomes one coherent court.", ["Sort bodies by category.", "Keep the Sun at the center.", "Explain why not everything is a planet."], ["Describe the Solar System as one family.", "Distinguish key body categories."], ["object_type", "main_host", "category_sort"], "Solar family classification reasoning."),
        diagnostic,
        "The Solar System is a dark court lit by one Great Lantern. Around that center move world riders, companion riders, rock swarm pieces, ice visitors, and smaller round riders.",
        "Commit to the Solar System as one organized Sun-centered family.",
        [prompt_block("What sits at the center of the Solar Court?", "The Great Lantern, which stands for the Sun."), prompt_block("What makes a moon different from a planet?", "A moon mainly orbits a larger world instead of the Sun as its main host.")],
        [prompt_block("Sort the bodies by what they orbit.", "Planets and dwarf planets orbit the Sun; moons orbit larger worlds."), prompt_block("Compare rocky and icy small bodies.", "Asteroids are mainly rocky; comets are icy visitors.")],
        ["Why is a family model stronger than a loose list of space objects?", "Why is it weak to call every Sun-orbiting body a planet?"],
        "Build the family structure first so later lessons on gravity, day, seasons, phases, and years all have a clear home.",
        concept,
        mastery,
        contract(
            concept_targets=["Describe the Solar System as one Sun-centered family.", "Distinguish planets, dwarf planets, moons, asteroids, and comets."],
            core_concepts=["The Sun is the central star of the Solar System.", "Planets and dwarf planets orbit the Sun, while moons orbit larger worlds.", "Asteroids are mainly rocky small bodies, while comets are icy visitors.", "Object categories matter because not everything orbiting the Sun is a planet."],
            prerequisite_lessons=[],
            misconception_focus=["sun_planet_confusion", "planet_category_confusion", "moon_planet_confusion", "comet_asteroid_confusion"],
            formulas=[relation("Solar System = one Sun-centered family", "Conceptual family rule for the module.", ["concept only"], "Use as the organizing statement."), relation("planet or dwarf planet -> orbits Sun", "Main-host rule for Sun-orbiting worlds.", ["concept only"], "Use when sorting planets and dwarf planets from moons.")],
            representations=[representation("words", "Names the Sun-centered family and the main body groups."), representation("diagram", "Shows the Great Lantern, world riders, companion riders, rock swarm, and ice visitor."), representation("formula", "Uses short concept rules for what orbits the Sun and what orbits a larger world.")],
            analogy_map=lantern_ring_map("the learner sorts planets, dwarf planets, moons, asteroids, and comets inside one Solar Court"),
            worked_examples=[worked("A round body orbits the Sun but has not cleared its orbital neighborhood. How should it be classified?", ["Notice that the body orbits the Sun directly.", "Notice that it is round.", "Use the neighborhood-clearing clue."], "It should be classified as a dwarf planet.", "A dwarf planet is a round Sun-orbiting world that has not cleared its neighborhood.", "This protects learners from collapsing dwarf planets into either planets or asteroids."), worked("A small body mainly orbits Earth rather than the Sun. What category fits best?", ["Ask what the body mainly orbits.", "Notice that its main host is a planet.", "Use the companion-rider rule."], "It is a moon.", "A moon is a companion rider that mainly orbits a larger world.", "This keeps planets and moons separated by orbit relationship.")],
            visual_assets=[visual("m14-l1-solar-court", "Build the Solar Court", "Show the Solar System as one Sun-centered family with several classes of bodies.", "The Solar Court visual keeps planets, dwarf planets, moons, asteroids, and comets together in one organized family.", diagram_type="solar_court")],
            animation_assets=[],
            simulation_contract=sim_contract("m14_l1_solar_court_sim", "solar_court_sort", "Sort each body into the right Solar Court category before explaining why it belongs there.", "Start with one example of each body type around the Great Lantern.", ["Sort by what the body is.", "Sort by what it mainly orbits."], "Watch for the difference between a world orbiting the Sun and a companion orbiting a larger world.", "The Solar System is one Sun-centered family made of several distinct object groups.", controls=[("object_type", "Body selector", "Lets learners compare planets, moons, asteroids, comets, and dwarf planets."), ("main_host", "Main host", "Shows whether the body mainly belongs to the Sun or to a larger world.")], readouts=[("Current classification", "Names the most accurate Solar Court category."), ("Host note", "Shows what the selected body mainly orbits.")]),
            reflection_prompts=["Explain why the Solar System is stronger as one Sun-centered family than as a random list of objects."],
            mastery_skills=["solar_family", "identify_sun", "classify_planet", "classify_moon", "classify_small_bodies"],
            variation_plan={"diagnostic": "Fresh attempts rotate between Sun-role, category, and main-host prompts.", "concept_gate": "Concept-gate retries alternate between category corrections and short host-orbit explanations.", "mastery": "Mastery varies summary and classification prompts before repeating a previous family."},
        ),
    )


def lesson_two() -> Dict[str, Any]:
    diagnostic = build_mcqs([
        ("M14L2_D1", "In the Lantern-Ring model, hub pull stands for...", ["gravity", "sunlight", "air resistance", "moonlight"], 0, "Hub pull is gravity.", ["gravity_random_motion_confusion"], ["identify_gravity"]),
        ("M14L2_D2", "A ring route stands for an...", ["orbit", "axis tilt", "day-night line", "phase shadow"], 0, "Ring routes are orbits.", ["orbit_track_confusion"], ["identify_orbit"]),
        ("M14L2_D3", "Which statement is strongest?", ["Orbits are pull-guided paths, not metal tracks in space.", "Orbits are rigid rails attached to the Sun.", "Planets need engines to stay in orbit.", "Gravity matters only for the Moon."], 0, "An orbit is a gravity-shaped path, not a solid rail.", ["orbit_track_confusion"], ["orbit_reasoning"]),
    ]) + build_shorts([
        ("M14L2_D4", "Why does a planet keep going around the Sun instead of only falling inward?", ["Because the planet has forward motion while gravity keeps turning that motion inward, so the path becomes an orbit.", "Because forward motion and the Sun's pull combine to make a curved ring route instead of a straight fall."], "Combine forward motion with gravity.", ["gravity_random_motion_confusion", "orbit_track_confusion"], ["orbit_reasoning"], acceptance_groups(["forward motion"], ["gravity", "hub pull"], ["curved path", "orbit"], ["not just fall"])),
    ])
    concept = build_mcqs([
        ("M14L2_C1", "Which force organizes both planets around the Sun and moons around planets?", ["gravity", "friction", "magnetism", "sound"], 0, "Gravity is the shared organizing pull.", ["gravity_random_motion_confusion"], ["moon_gravity"]),
        ("M14L2_C2", "If a moving body is continually pulled inward while it also keeps moving forward, the best path description is...", ["curved", "still", "random", "vertical"], 0, "That is the core orbit idea.", ["gravity_random_motion_confusion"], ["orbit_reasoning"]),
    ]) + build_shorts([
        ("M14L2_C3", "Why does the same gravity idea work for both planets and moons?", ["Because gravity can guide any orbiting body, so the Sun holds planets and planets hold moons.", "Because hub pull is the same basic kind of attraction whether the central body is the Sun or a planet."], "Name both Sun-planets and planet-moons.", ["gravity_random_motion_confusion"], ["moon_gravity", "identify_gravity"], acceptance_groups(["gravity", "hub pull"], ["Sun", "planets"], ["planet", "moons"], ["same basic idea", "works for both"])),
    ])
    mastery = build_mcqs([
        ("M14L2_M1", "Best one-line summary of a ring route:", ["a pull-guided orbit shaped by gravity", "a bright stripe made of sunlight", "a rigid metal circle in space", "the Moon's shadow"], 0, "Keep the orbit definition short and physical.", ["orbit_track_confusion"], ["identify_orbit"]),
        ("M14L2_M2", "Which statement best protects against the track misconception?", ["The orbit is a path produced by gravity and motion, not a built structure.", "The orbit is a strong wire holding the planet up.", "The planet moves only because the Sun drags it around.", "Only circles count as orbits."], 0, "Use gravity-and-motion language.", ["orbit_track_confusion"], ["identify_orbit"]),
        ("M14L2_M3", "Which object pair is best explained by the same gravity story?", ["Earth around the Sun and the Moon around Earth", "day and night", "summer and winter", "new moon and full moon"], 0, "Both are gravity-guided orbits.", ["gravity_random_motion_confusion"], ["moon_gravity"]),
    ]) + build_shorts([
        ("M14L2_M4", "Summarize why planets orbit the Sun in one strong sentence.", ["Planets orbit because their forward motion and the Sun's gravity combine to make curved paths around the Sun.", "A planet keeps moving forward while the Sun's pull keeps bending the path into an orbit."], "Keep forward motion and gravity together.", ["gravity_random_motion_confusion", "orbit_track_confusion"], ["orbit_reasoning"], acceptance_groups(["forward motion"], ["gravity", "Sun's pull", "hub pull"], ["curved path", "orbit"], ["around the Sun"])),
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
            worked_examples=[worked("A learner says, 'The orbit must be a built track in space.' How do you correct that idea?", ["Ask what actually provides the turning effect.", "Replace the track picture with gravity plus forward motion.", "Restate the orbit as a path rather than a structure."], "The orbit is a gravity-guided path, not a built track.", "The curve comes from the inward pull acting while the body keeps moving forward.", "This protects the learner from carrying a rail-model misconception into later astronomy lessons."), worked("Why can the same idea explain Earth around the Sun and the Moon around Earth?", ["Identify the central body in each case.", "Notice that gravity is the pull in both cases.", "State the shared orbit rule."], "Both are gravity-guided orbits around a central body.", "The host body changes, but the same hub-pull idea keeps working.", "This helps the learner reuse one orbit principle instead of memorizing two unrelated stories.")],
            visual_assets=[visual("m14-l2-hub-pull-routes", "Hub pull and ring routes", "Show how gravity and forward motion cooperate to shape an orbit without any physical rail in space.", "The ring-route visual keeps the orbit tied to pull and motion so the path feels caused rather than built.", diagram_type="gravity_rings")],
            animation_assets=[],
            simulation_contract=sim_contract("m14_l2_hub_pull_routes_sim", "hub_pull_routes", "Change pull strength and forward motion until the ring route makes sense as a gravity-shaped path.", "Start with one world rider moving around the Great Lantern on a stable ring route.", ["Raise the pull strength.", "Lower the forward motion."], "Watch for the route changing because the path is caused by gravity and motion together.", "An orbit is a pull-guided path rather than a built track in space.", controls=[("pull_strength", "Hub pull", "Changes how strongly the route bends inward."), ("forward_motion", "Forward motion", "Sets how strongly the body keeps moving along the path.")], readouts=[("Orbit shape", "Summarizes how curved the current route is."), ("Reasoning note", "Keeps the learner focused on gravity plus motion instead of track language.")]),
            reflection_prompts=["Explain why a ring route is stronger as a pull-guided path than as a fixed track."],
            mastery_skills=["identify_gravity", "identify_orbit", "orbit_reasoning", "moon_gravity", "gravity_motion_bridge"],
            variation_plan={"diagnostic": "Fresh attempts rotate between pull, path, and motion questions.", "concept_gate": "Concept-gate retries alternate between planet-Sun and moon-planet comparisons.", "mastery": "Mastery varies misconception corrections and orbit summaries before repeating an earlier stem."},
        ),
    )


def lesson_three() -> Dict[str, Any]:
    diagnostic = build_mcqs([
        ("M14L3_D1", "In the Lantern-Ring model, spin on a rod stands for...", ["rotation", "orbit", "gravity", "phase"], 0, "Spin on a rod stands for rotation.", ["rotation_orbit_confusion"], ["identify_rotation"]),
        ("M14L3_D2", "Day and night on Earth happen mainly because Earth...", ["rotates", "orbits the Sun once per day", "gets closer to the Sun", "changes Moon phase"], 0, "Day and night come from rotation.", ["rotation_orbit_confusion"], ["day_night_reasoning"]),
        ("M14L3_D3", "If Earth rotates 360 degrees in 24 hours, it turns about how many degrees per hour?", ["15 degrees", "24 degrees", "30 degrees", "6 degrees"], 0, "360 / 24 = 15.", ["rotation_orbit_confusion"], ["rotation_rate"]),
    ]) + build_shorts([
        ("M14L3_D4", "Why is it weak to say day and night happen because Earth goes around the Sun?", ["Because Earth's orbit takes about a year, while day and night come from Earth's daily rotation.", "Because the 24-hour cycle is made by spin, not by one yearly trip around the Sun."], "Contrast daily rotation with yearly orbit.", ["rotation_orbit_confusion"], ["day_night_reasoning"], acceptance_groups(["rotation", "spin"], ["24-hour", "daily"], ["orbit", "year"], ["not", "rather than"])),
    ])
    concept = build_mcqs([
        ("M14L3_C1", "How many hours are needed for Earth to rotate about 90 degrees?", ["6 hours", "3 hours", "12 hours", "18 hours"], 0, "90 / 15 = 6.", ["rotation_orbit_confusion"], ["rotation_rate"]),
        ("M14L3_C2", "Which phrase best matches the spin rod?", ["rotation axis", "orbit path", "sunlight beam", "phase shadow"], 0, "The spin rod is the rotation axis.", ["rotation_orbit_confusion"], ["identify_rotation"]),
    ]) + build_shorts([
        ("M14L3_C3", "Explain how rotation creates the day-night cycle.", ["As Earth rotates, a place moves into the lit half and later into the dark half, creating day and night.", "Earth's spin turns places toward the Sun and then away from it, so the local sky changes from day to night."], "Use turn-toward and turn-away language.", ["rotation_orbit_confusion"], ["day_night_reasoning"], acceptance_groups(["rotate", "spin"], ["toward the Sun", "into sunlight"], ["away from the Sun", "dark half"], ["day", "night"])),
    ])
    mastery = build_mcqs([
        ("M14L3_M1", "If Earth turns 45 degrees in the simple model, about how much time has passed?", ["3 hours", "6 hours", "9 hours", "12 hours"], 0, "45 / 15 = 3.", ["rotation_orbit_confusion"], ["rotation_rate"]),
        ("M14L3_M2", "What stays true at every moment in the day-night story?", ["Half of Earth is lit and half is dark.", "All of Earth is lit at noon.", "All of Earth is dark at midnight.", "Only the equator gets sunlight."], 0, "The split between day-face and night-face is always present.", ["day_night_sun_motion_confusion"], ["day_night_reasoning"]),
        ("M14L3_M3", "How many hours are in half of Earth's rotation period?", ["12 hours", "6 hours", "18 hours", "24 hours"], 0, "Half of 24 hours is 12 hours.", ["rotation_orbit_confusion"], ["rotation_period"]),
    ]) + build_shorts([
        ("M14L3_M4", "Summarize day and night in one strong sentence.", ["Day and night happen because Earth rotates, so places turn toward the Sun and then away from it.", "The day-night cycle is Earth's spin carrying each place through the lit half and the dark half."], "Keep rotation and facing-toward-away together.", ["rotation_orbit_confusion"], ["day_night_reasoning"], acceptance_groups(["rotation", "spin"], ["toward the Sun", "lit half"], ["away from the Sun", "dark half"], ["day", "night"])),
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
            worked_examples=[worked("Earth rotates 360 degrees in 24 hours. How many degrees does it rotate in 6 hours?", ["Use 360 degrees in 24 hours as 15 degrees per hour.", "Multiply 15 by 6.", "State the quarter-turn result."], "90 degrees", "A quarter of the full 24-hour rotation is 90 degrees.", "This helps learners connect the day-night story to a simple measurable rate."), worked("A learner says, 'Sunrise happens because Earth moves to a new place in its yearly orbit.' How do you correct that?", ["Compare the daily cycle with the yearly orbit time.", "Track one place through one spin.", "Restate sunrise as turning into sunlight."], "Sunrise is caused by rotation, not the yearly orbit.", "The 24-hour change belongs to Earth spinning, while the orbit takes about a year.", "This protects the lesson from collapsing daily and yearly motion into one blurred idea.")],
            visual_assets=[visual("m14-l3-spin-for-daylight", "Spin for daylight", "Show one lit half, one dark half, and the spin rod so the daily cycle stays tied to rotation.", "The day-night visual keeps the Sun fixed and lets Earth's own spin do the explanatory work.", diagram_type="day_night_rotation")],
            animation_assets=[],
            simulation_contract=sim_contract("m14_l3_spin_for_daylight_sim", "spin_for_daylight", "Rotate the world until the daily cycle feels like a spin story instead of an orbit story.", "Start with a city near the boundary between day-face and night-face.", ["Advance the world by 3 hours.", "Advance the world by 6 hours."], "Watch the city move into sunlight and later back into darkness because of spin, not because of the yearly lap.", "Day and night are produced by Earth's rotation on its axis.", controls=[("rotation_angle", "Rotation angle", "Moves the home world through the lit and dark halves."), ("rotation_rate", "Spin rate", "Helps compare quarter-turn, half-turn, and full-turn timing.")], readouts=[("Local side", "Shows whether the city is on the day-face or night-face."), ("Elapsed time", "Converts the spin angle into approximate hours.")]),
            reflection_prompts=["Explain why day and night are stronger as a spin story than as an orbit story."],
            mastery_skills=["identify_rotation", "rotation_period", "rotation_rate", "day_night_reasoning", "rotation_orbit_compare"],
            variation_plan={"diagnostic": "Fresh attempts rotate between cause-of-day-night and simple rotation-rate questions.", "concept_gate": "Concept-gate retries alternate between city-rotation reasoning and timing calculations.", "mastery": "Mastery varies summary, timing, and misconception-correction tasks before repeating an earlier day-night family."},
        ),
    )


def lesson_four() -> Dict[str, Any]:
    diagnostic = build_mcqs([
        ("M14L4_D1", "The main cause of Earth's seasons is...", ["axial tilt", "distance from the Sun changing a lot each season", "Moonlight", "Earth spinning faster in summer"], 0, "Seasons come from axial tilt, not distance.", ["season_distance_confusion"], ["season_reasoning"]),
        ("M14L4_D2", "Earth's axis is tilted by about...", ["23.4 degrees", "90 degrees", "5 degrees", "180 degrees"], 0, "Earth's axial tilt is about 23.4 degrees.", ["tilt_direction_confusion"], ["tilt_value"]),
        ("M14L4_D3", "When the Northern Hemisphere tilts toward the Sun, it is generally...", ["summer there", "winter there", "night all day", "a full moon"], 0, "Tilt toward means more direct sunlight and longer days.", ["hemisphere_season_confusion"], ["season_reasoning"]),
    ]) + build_shorts([
        ("M14L4_D4", "Why is it weak to explain summer by saying Earth is simply closer to the Sun then?", ["Because the seasons are mainly caused by axial tilt and changing sunlight angle, not by a simple distance change.", "Because Earth's tilted axis makes one hemisphere lean toward the Sun and get more direct sunlight, which is stronger than a distance explanation."], "Use tilt and sunlight-angle language.", ["season_distance_confusion"], ["season_reasoning"], acceptance_groups(["tilt", "axial tilt"], ["sunlight angle", "more direct sunlight", "leans toward"], ["not", "rather than"], ["distance", "closer to the Sun"])),
    ])
    concept = build_mcqs([
        ("M14L4_C1", "If Earth had no axial tilt, the best simple prediction is that...", ["the usual seasonal contrast would be much weaker", "Earth would stop orbiting", "day and night would vanish", "the Moon would stop having phases"], 0, "Tilt is the main cause of the yearly seasonal contrast.", ["season_distance_confusion"], ["season_reasoning"]),
        ("M14L4_C2", "About six months after December in the Northern Hemisphere, the season is most likely...", ["summer", "winter again", "always autumn", "nighttime"], 0, "Half a year later the geometry reverses.", ["hemisphere_season_confusion"], ["hemisphere_compare"]),
    ]) + build_shorts([
        ("M14L4_C3", "Why do opposite hemispheres get opposite seasons?", ["Because when one hemisphere tilts toward the Sun, the other tilts away from it.", "Because the same axial tilt makes one side lean toward the lantern while the other side leans away."], "Use toward-and-away language.", ["hemisphere_season_confusion"], ["hemisphere_compare"], acceptance_groups(["one hemisphere"], ["toward the Sun", "leans toward"], ["other hemisphere"], ["away from the Sun", "leans away"], ["opposite seasons", "different seasons"])),
    ])
    mastery = build_mcqs([
        ("M14L4_M1", "If it is June and the Northern Hemisphere is tilted toward the Sun, the Southern Hemisphere is most likely experiencing...", ["winter", "summer", "noon", "full moon"], 0, "Opposite hemispheres have opposite seasons.", ["hemisphere_season_confusion"], ["hemisphere_compare"]),
        ("M14L4_M2", "Which statement best protects against the distance misconception?", ["Seasons are driven mainly by tilt and sunlight angle.", "Seasons happen because Earth stops rotating.", "Seasons are caused by the Moon's shadow.", "Seasons happen because the Sun moves around Earth."], 0, "Use tilt and sunlight angle language.", ["season_distance_confusion"], ["season_reasoning"]),
        ("M14L4_M3", "Earth's tilt is closest to...", ["23.4 degrees", "45 degrees", "75 degrees", "180 degrees"], 0, "Keep the tilt value visible.", ["tilt_direction_confusion"], ["tilt_value"]),
    ]) + build_shorts([
        ("M14L4_M4", "Summarize the cause of seasons in one strong sentence.", ["Seasons happen because Earth's tilted axis makes each hemisphere receive different sunlight angles and day lengths during the year.", "The seasonal cycle comes from axial tilt, which makes one hemisphere lean toward the Sun and later away from it."], "Keep tilt, sunlight angle, and the year together.", ["season_distance_confusion"], ["season_reasoning"], acceptance_groups(["seasons"], ["tilt", "tilted axis", "axial tilt"], ["sunlight angle", "more direct sunlight", "day length"], ["during the year", "yearly", "as Earth orbits"])),
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
            worked_examples=[worked("It is June and the Northern Hemisphere is tilted toward the Sun. What season is the Southern Hemisphere most likely experiencing?", ["Notice that the hemispheres tilt in opposite ways at the same moment.", "If the north is tilted toward the Sun, the south is tilted away.", "Infer the opposite season."], "Winter in the Southern Hemisphere", "Opposite hemispheres experience opposite seasonal geometry.", "This protects learners from applying the same season to both hemispheres at once."), worked("A learner says, 'Summer happens because Earth is closest to the Sun then.' How do you correct the explanation?", ["Keep the axis tilt visible.", "Compare sunlight angle rather than just distance.", "State the stronger tilt-based explanation."], "Summer is better explained by axial tilt and more direct sunlight.", "The tilted hemisphere gets more direct sunlight and longer days, which is stronger than a distance-only story.", "This is the central misconception shield for the seasons lesson.")],
            visual_assets=[visual("m14-l4-season-switch", "Season switch", "Show June and December positions with the same axis direction so the season geometry stays readable.", "The season-switch diagram makes the fixed tilted axis visible so the lesson does not collapse back into a distance-only story.", diagram_type="seasons_tilt", meta={"tilt_deg": 23.4})],
            animation_assets=[],
            simulation_contract=sim_contract("m14_l4_season_switch_sim", "season_switch", "Move the tilted world around the Sun until the seasonal switch between hemispheres feels inevitable.", "Start with Earth in a June-like position with the Northern Hemisphere leaning toward the Sun.", ["Move to the opposite side of the orbit.", "Switch the hemisphere label."], "Watch the same tilted axis favor one hemisphere and then the other as Earth moves around the Sun.", "Seasons come from axial tilt and changing sunlight angle, not from a simple distance change.", controls=[("orbit_position", "Year-lap position", "Moves Earth to different places around the Sun."), ("axial_tilt", "Tilt rod", "Sets the lean that creates the season contrast.")], readouts=[("Favored hemisphere", "Shows which hemisphere is tilted more toward the Sun."), ("Season check", "Labels the likely seasonal direction for the current hemisphere view.")]),
            reflection_prompts=["Explain why tilt is stronger than distance as the cause of seasons."],
            mastery_skills=["identify_tilt", "tilt_value", "season_reasoning", "hemisphere_compare", "season_distance_correction"],
            variation_plan={"diagnostic": "Fresh attempts rotate between tilt-value, hemisphere, and misconception questions.", "concept_gate": "Concept-gate retries alternate between June-December comparisons and no-tilt cases.", "mastery": "Mastery varies hemisphere switches, summary explanations, and tilt-value prompts before repeating an earlier season family."},
        ),
    )


def lesson_five() -> Dict[str, Any]:
    diagnostic = build_mcqs([
        ("M14L5_D1", "Moonlight is mainly...", ["reflected sunlight", "light made by the Moon itself", "Earth's shadow glowing", "a form of sound"], 0, "The Moon reflects sunlight.", ["moon_self_light_confusion"], ["moon_light_source"]),
        ("M14L5_D2", "At any moment the Moon is...", ["half lit by the Sun", "completely lit", "completely dark", "lit only during full moon"], 0, "The Sun always lights half of the Moon.", ["moon_phase_shadow_confusion"], ["phase_reasoning"]),
        ("M14L5_D3", "Ordinary Moon phases happen mainly because...", ["we see different amounts of the Moon's lit half", "Earth's shadow covers different pieces each week", "the Moon changes how much light it makes", "the Sun changes color"], 0, "Phase is a viewing-geometry story.", ["moon_phase_shadow_confusion"], ["phase_reasoning"]),
    ]) + build_shorts([
        ("M14L5_D4", "Why is it weak to say ordinary Moon phases are caused by Earth's shadow?", ["Because ordinary phases come from our changing view of the Moon's sunlit half, while Earth's shadow matters only during a lunar eclipse.", "Because the Moon is always half lit by the Sun and the phase depends on viewing geometry, not on Earth's shadow covering it each week."], "Use lit-half and eclipse language.", ["moon_phase_shadow_confusion"], ["phase_shadow_correction"], acceptance_groups(["phases"], ["view", "see different amounts", "viewing geometry"], ["lit half", "sunlit half"], ["Earth's shadow"], ["eclipse"])),
    ])
    concept = build_mcqs([
        ("M14L5_C1", "What phase is most likely when the Moon appears mostly lit and is increasing in illumination?", ["waxing gibbous", "waning crescent", "new moon", "third quarter"], 0, "Waxing means increasing, and gibbous means more than half lit.", ["moon_phase_shadow_confusion"], ["phase_sequence"]),
        ("M14L5_C2", "What does 'first quarter' mainly refer to?", ["the Moon being about a quarter of the way around its orbit from new moon", "only a quarter of the Moon being lit", "Earth's shadow covering most of the Moon", "the Moon making only quarter brightness"], 0, "Quarter names the orbital position idea.", ["quarter_moon_name_confusion"], ["phase_sequence"]),
    ]) + build_shorts([
        ("M14L5_C3", "Explain why the Moon is always half lit even though we do not always see a full moon.", ["Because the Sun always lights half of the Moon, but from Earth we see different fractions of that lit half as the Moon moves around us.", "Because the amount lit by the Sun stays half, while our viewing angle changes during the Moon's orbit."], "Keep Sun lighting and Earth viewing angle together.", ["moon_phase_shadow_confusion"], ["phase_reasoning"], acceptance_groups(["Sun", "lights", "half lit"], ["Earth", "we see", "viewing angle"], ["different amounts", "different fractions", "lit half"])),
    ])
    mastery = build_mcqs([
        ("M14L5_M1", "About two weeks after new moon, the phase is closest to...", ["full moon", "new moon again", "third quarter", "waning crescent"], 0, "Full moon is about half a cycle after new moon.", ["moon_phase_shadow_confusion"], ["phase_timing"]),
        ("M14L5_M2", "Which event actually needs Earth's shadow to line up with the Moon?", ["lunar eclipse", "every ordinary phase", "waxing crescent", "first quarter"], 0, "Earth's shadow is an eclipse idea.", ["moon_phase_shadow_confusion"], ["phase_shadow_correction"]),
        ("M14L5_M3", "What changes during the ordinary monthly phase cycle?", ["our view of the Moon's lit half", "how much of the Moon the Sun lights", "the Moon's own light production", "Earth's orbit around the Sun"], 0, "The changing view is the central idea.", ["moon_phase_shadow_confusion"], ["phase_reasoning"]),
    ]) + build_shorts([
        ("M14L5_M4", "Summarize Moon phases in one strong sentence.", ["Moon phases happen because we see different amounts of the Moon's sunlit half as it orbits Earth.", "The Moon is always half lit by the Sun, and the changing phase is our changing view of that lit half."], "Keep orbit and changing view together.", ["moon_phase_shadow_confusion"], ["phase_reasoning"], acceptance_groups(["Moon phases"], ["see different amounts", "changing view"], ["sunlit half", "lit half", "half lit"], ["orbits Earth", "moves around Earth"])),
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
            worked_examples=[worked("The Moon is on the opposite side of Earth from the Sun. What phase is most likely?", ["Notice that the Moon's sunlit half faces Earth in this geometry.", "Use the opposite-side clue.", "Name the phase."], "Full moon", "When the Moon is opposite the Sun, we see most of its lit half.", "This gives learners a strong geometry anchor for the full moon without using shadow language."), worked("A learner says, 'First quarter means only a quarter of the Moon is lit.' How do you correct that?", ["Notice that the Sun still lights half of the Moon.", "Remember that quarter names the orbital position in the cycle.", "State what we usually see at first quarter."], "First quarter means the Moon is about a quarter of the way around its orbit, while we see about half of the lit half.", "The name is about the phase cycle position, not a quarter-lit Moon.", "This protects against a persistent Moon-phase naming confusion.")],
            visual_assets=[visual("m14-l5-moon-face-challenge", "Moon face challenge", "Show Earth, Moon, the Sun, and one named Moon position so the visible phase is read from geometry rather than shadow.", "The companion-face diagram keeps the Moon always half lit and lets the viewing angle do the explanatory work.", diagram_type="moon_phases", meta={"moon_position": 2})],
            animation_assets=[],
            simulation_contract=sim_contract("m14_l5_moon_face_sim", "moon_face_challenge", "Move the companion rider until the current phase can be predicted from geometry alone.", "Start with Earth and Moon under one fixed Great Lantern.", ["Place the Moon at new, quarter, and full positions.", "Switch between waxing and waning positions."], "Watch the visible lit fraction change because your viewpoint changes while the Sun still lights half the Moon.", "Moon phases are a Sun-Earth-Moon viewing story, not an Earth-shadow story.", controls=[("moon_position", "Moon position", "Moves the companion rider around Earth."), ("phase_name", "Phase label", "Checks whether the learner links geometry to the correct phase word.")], readouts=[("Current phase", "Names the phase suggested by the current Moon position."), ("Light source", "Reminds the learner that the Sun lights the Moon.")]),
            reflection_prompts=["Explain why Moon phases are stronger as a viewing story than as a shadow story."],
            mastery_skills=["moon_light_source", "phase_reasoning", "phase_sequence", "phase_shadow_correction", "moon_geometry_view"],
            variation_plan={"diagnostic": "Fresh attempts rotate between light-source, geometry, and misconception prompts.", "concept_gate": "Concept-gate retries alternate between new-full-quarter geometry and waxing-waning language.", "mastery": "Mastery varies sequence, timing, summary, and misconception-correction tasks before repeating an earlier Moon-phase family."},
        ),
    )


def lesson_six() -> Dict[str, Any]:
    diagnostic = build_mcqs([
        ("M14L6_D1", "In the Lantern-Ring model, a year lap stands for...", ["orbital period", "rotation axis", "day-night line", "Moon phase"], 0, "A year lap is the orbital period.", ["outer_orbit_same_period_confusion"], ["identify_orbital_period"]),
        ("M14L6_D2", "Ring reach stands for...", ["orbital distance", "gravity strength only", "day length", "phase size"], 0, "Ring reach is orbital distance.", ["orbital_distance_period_confusion"], ["identify_orbital_distance"]),
        ("M14L6_D3", "Which world usually has the longer year lap?", ["the one on the farther ring", "the one closer to the Sun", "both always the same", "the one spinning faster"], 0, "Farther worlds usually take longer to complete an orbit.", ["outer_orbit_same_period_confusion"], ["distance_period_reasoning"]),
    ]) + build_shorts([
        ("M14L6_D4", "Why does a farther ring usually mean a longer year lap in this module?", ["Because a world on a farther orbit usually takes longer to travel around the Sun once.", "Because greater ring reach is linked qualitatively to a longer orbital period."], "Use farther-orbit and longer-time language.", ["orbital_distance_period_confusion"], ["distance_period_reasoning"], acceptance_groups(["farther orbit", "greater ring reach", "farther ring"], ["longer", "takes longer"], ["around the Sun", "one orbit", "orbital period"])),
    ])
    concept = build_mcqs([
        ("M14L6_C1", "If an inner world completes 4 laps while an outer world completes 1 in the same interval, which has the shorter orbital period?", ["the inner world", "the outer world", "both the same", "cannot be decided"], 0, "More laps in the same time means a shorter orbital period.", ["outer_orbit_same_period_confusion"], ["compare_orbital_periods"]),
        ("M14L6_C2", "Which term best names the time for one full orbit?", ["orbital period", "axial tilt", "new moon", "rotation axis"], 0, "That time is the orbital period.", ["outer_orbit_same_period_confusion"], ["identify_orbital_period"]),
    ]) + build_shorts([
        ("M14L6_C3", "Explain the qualitative distance-period rule in one sentence.", ["Worlds on farther rings usually take longer to complete one orbit around the Sun.", "Greater orbital distance usually goes with a longer orbital period."], "Use farther-distance and longer-period language.", ["orbital_distance_period_confusion"], ["distance_period_reasoning"], acceptance_groups(["farther", "greater orbital distance", "farther ring"], ["longer", "takes longer"], ["orbit", "orbital period", "year"])),
    ])
    mastery = build_mcqs([
        ("M14L6_M1", "A planet on a farther ring than Earth is most likely to have a year that is...", ["longer than Earth's", "shorter than Earth's", "exactly the same", "equal to one day"], 0, "Farther ring reach usually means longer year lap.", ["outer_orbit_same_period_confusion"], ["compare_orbital_periods"]),
        ("M14L6_M2", "Which statement best protects against 'all planets take about a year'?", ["Year length depends on orbital distance, so different worlds can have very different orbital periods.", "All worlds take about one Earth year.", "Only Earth really has a year.", "Year length is set by Moon phases."], 0, "Different ring reach means different year length.", ["outer_orbit_same_period_confusion"], ["distance_period_reasoning"]),
        ("M14L6_M3", "Which quantity should you compare if you want to know which planet takes longer to go around the Sun?", ["orbital period", "rotation rate", "phase", "shadow length"], 0, "Year length is orbital period.", ["outer_orbit_same_period_confusion"], ["identify_orbital_period"]),
    ]) + build_shorts([
        ("M14L6_M4", "Summarize the outer-lap idea in one strong sentence.", ["Farther worlds usually take longer to complete one orbit around the Sun, so their years are usually longer.", "Greater ring reach usually means a longer year lap around the Great Lantern."], "Keep distance and period together.", ["orbital_distance_period_confusion"], ["distance_period_reasoning"], acceptance_groups(["farther", "greater ring reach", "outer"], ["longer", "takes longer"], ["orbit", "orbital period", "year"])),
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
            worked_examples=[worked("An outer world and an inner world are watched for the same amount of time. The inner world completes 3 laps while the outer world completes 1. Which has the shorter orbital period?", ["Count the laps in the same time interval.", "Notice that more completed laps means each lap takes less time.", "State which world has the shorter year."], "The inner world has the shorter orbital period.", "Completing more laps in the same time means each orbit is shorter.", "This helps learners compare orbital periods without needing a memorized planet table."), worked("A learner says, 'All planets should take about a year because they all go around the Sun.' How do you correct that?", ["Compare ring reach first.", "Note that different orbital distances mean different year laps.", "State the qualitative rule."], "Different planets can have very different years because farther orbits usually take longer.", "The shared host is the Sun, but the orbital distances are not the same, so the periods are not the same either.", "This closes the module with a general pattern instead of a single-Earth assumption.")],
            visual_assets=[visual("m14-l6-outer-lap-puzzle", "Outer lap puzzle", "Show inner and outer rings with shorter and longer year-lap arrows so the distance-period pattern stays visual.", "The outer-lap comparison makes year length a ring-distance pattern instead of a planet list to memorize.", diagram_type="orbit_distance_period")],
            animation_assets=[],
            simulation_contract=sim_contract("m14_l6_outer_lap_sim", "outer_lap_puzzle", "Compare inner and outer rings until longer years and farther distances feel like one connected pattern.", "Start with one inner world and one outer world at the same side of the Sun.", ["Count completed laps after one shared time interval.", "Move the outer world farther away."], "Watch the inner world complete more laps in the same interval while the outer world takes longer for one full orbit.", "Farther solar rings usually go with longer year laps.", controls=[("inner_distance", "Inner ring reach", "Sets how close the inner world is to the Sun."), ("outer_distance", "Outer ring reach", "Sets how far the outer world is from the Sun.")], readouts=[("Inner year", "Summarizes the inner world's orbital period qualitatively."), ("Outer year", "Summarizes the outer world's orbital period qualitatively.")]),
            reflection_prompts=["Explain why a farther ring usually means a longer year lap."],
            mastery_skills=["identify_orbital_period", "identify_orbital_distance", "distance_period_reasoning", "compare_orbital_periods", "year_lap_compare"],
            variation_plan={"diagnostic": "Fresh attempts rotate between year-lap, ring-reach, and inner-versus-outer comparisons.", "concept_gate": "Concept-gate retries alternate between orbit-distance reasoning and lap-count comparisons.", "mastery": "Mastery varies summary, comparison, and misconception-correction tasks before repeating an earlier orbital-period family."},
        ),
    )


M14_SPEC = {
    "authoring_standard": AUTHORING_STANDARD_V1,
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
    authoring_standard=AUTHORING_STANDARD_V1,
    plan_assets=True,
    public_base="/lesson_assets",
)


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

