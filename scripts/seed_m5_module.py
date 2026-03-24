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


M5_MODULE_ID = "M5"
M5_CONTENT_VERSION = "20260323_m5_particle_internal_energy_v2"
M5_MODULE_TITLE = "Particle Model and Internal Energy"
M5_ALLOWLIST = [
    "particle_size_heating_confusion",
    "liquid_spacing_confusion",
    "particle_bulk_property_confusion",
    "particle_motion_state_confusion",
    "brownian_self_motion_confusion",
    "temperature_internal_energy_confusion",
    "same_temperature_same_internal_energy_confusion",
    "state_change_energy_confusion",
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
    allowed = set(M5_ALLOWLIST)
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
) -> Dict[str, Any]:
    return {
        "asset_id": asset_id,
        "concept": concept,
        "phase_key": phase_key,
        "title": title,
        "purpose": purpose,
        "caption": caption,
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
        "The core comparison readouts are not overlapped by arrows, traces, or particles.",
        "The state or meter labels remain readable without needing to infer hidden text.",
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
        normalized_representations.insert(0, {"kind": "words", "purpose": "States the particle-model idea in plain language before symbols."})
    if "formula" not in normalized_kinds:
        anchor = str(formulas[0].get("equation") or "").strip() if formulas else "the formal statement"
        normalized_representations.append({"kind": "formula", "purpose": f"Compresses the key relation into {anchor} after the model is clear."})
    if not ({item.get("kind") for item in normalized_representations} & {"diagram", "graph", "table", "model", "equation_story"}):
        normalized_representations.append({"kind": "diagram", "purpose": "Keeps the particle arrangement or comparison visible while variables change."})

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


def pulse_plaza_map(model_focus: str) -> Dict[str, Any]:
    return {
        "model_name": "Pulse-Plaza Model of Matter",
        "focus": model_focus,
        "comparison": f"The Pulse-Plaza keeps states of matter, Brownian motion, temperature, and internal energy in one particle world by tracking jiggle, grip, and whole-system store in {model_focus}.",
        "mapping": [
            "Micro-pucks -> particles",
            "Grip Links -> intermolecular attractions",
            "Jiggle Motion -> random particle motion",
            "Pulse Level -> temperature",
            "Plaza Store -> internal energy",
        ],
        "limit": "The analogy organizes the particle picture, but the formal physics terms still matter when you explain the state, the evidence, or the energy change.",
        "prediction_prompt": f"Using the Pulse-Plaza alone, predict what should happen when {model_focus}.",
    }


def lesson_l1() -> Dict[str, Any]:
    return {
        "id": "M5_L1",
        "title": "Micro-pucks and Matter Rules",
        "sim": {
            "lab_id": "m5_particle_rules_lab",
            "title": "Pulse-Plaza starter",
            "description": "Change pulse, grip, and crowd size while checking that particle size stays fixed and that bulk properties do not belong to one particle.",
            "instructions": [
                "Turn the Pulse Dial up and down without letting the puck size change.",
                "Compare crowded and less-crowded plazas while checking whether one particle becomes wet, hard, or soft.",
                "Use the state indicator to describe spacing, motion, and attraction together.",
            ],
            "outcomes": [
                "particle_size_heating_confusion",
                "particle_bulk_property_confusion",
                "particle_motion_state_confusion",
            ],
            "fields": ["pulse_level", "grip_level", "crowd_size", "state_mode", "particle_size"],
            "depth": "number of changes explained as motion or spacing changes rather than particle-size or bulk-property changes",
        },
        "analogy_text": (
            "The Pulse-Plaza begins with one non-negotiable rule: the micro-pucks never get bigger. The Pulse Dial changes how lively they are, "
            "and the Grip Dial changes how strongly neighbors pull together, but a single puck never becomes wet, hard, bigger, or hotter in the bulk-material sense."
        ),
        "commitment_prompt": "Before you answer, decide whether the statement belongs to one particle or to the whole crowd.",
        "micro_prompts": [
            prompt_block("What changes when the plaza is heated?", "Name motion or spacing changes, not particle-size changes."),
            prompt_block("Can one particle be wet or hard by itself?", "Keep bulk properties separate from single particles."),
            prompt_block("What decides the state pattern in the plaza?", "Use the tug-of-war between jiggle and grip."),
        ],
        "inquiry": [
            prompt_block("Raise the Pulse Dial. What changes, and what stays fixed?", "State that puck size stays fixed."),
            prompt_block("Now change the Grip Dial. Which part of the crowd story changes?", "Use attraction, spacing, and movement language."),
            prompt_block("Compare the same pulse in two crowd sizes. Which statements belong to the whole system rather than one puck?", "Separate one-particle and crowd-level claims."),
        ],
        "recon_prompts": [
            "Particles do not get bigger when heated; their motion and spacing pattern change.",
            "A single particle does not have bulk properties like wetness or hardness on its own.",
            "State is decided by the balance between particle motion and attraction.",
        ],
        "capsule_prompt": "Use the Pulse-Plaza rules to stop single-particle and whole-material ideas from collapsing together.",
        "capsule_checks": [
            mcq("M5L1_C1", "Which statement is strongest?", ["Heating makes the particles bigger", "Heating changes motion and spacing, not particle size", "Heating makes each particle wet", "Heating removes all attractions"], 1, "Keep puck size fixed and name the changing motion.", ["particle_size_heating_confusion"], skill_tags=["particle_size_rule"]),
            mcq("M5L1_C2", "Which property belongs to the whole material rather than one particle?", ["being wet", "having mass", "existing", "moving"], 0, "Wetness is a bulk result of many particles together.", ["particle_bulk_property_confusion"], skill_tags=["bulk_vs_particle"]),
            mcq("M5L1_C3", "What decides whether the crowd looks locked, sliding, or drifting?", ["the color of the pucks only", "the balance between jiggle and grip", "the size of each puck", "the time of day"], 1, "State depends on motion and attraction together.", ["particle_motion_state_confusion"], skill_tags=["state_from_balance"]),
            short("M5L1_C4", "Why is 'particles get bigger when heated' weak?", ["because heating changes motion and spacing, not particle size", "because the particles stay the same size and only their motion or separation changes"], "Use motion-and-spacing language together.", ["particle_size_heating_confusion"], acceptance_rules=acceptance_groups(["same size", "stay the same size", "do not get bigger", "particle size stays fixed"], ["motion", "move faster", "jiggle"], ["spacing", "further apart", "separation", "arrangement"]), skill_tags=["particle_size_rule"]),
            mcq("M5L1_C5", "Which statement keeps the particle model accurate for a liquid?", ["Its particles are very far apart like a gas", "Its particles are close together but can move past one another", "Its particles are larger than solid particles", "Its particles stop moving"], 1, "Liquid means close and mobile together.", ["liquid_spacing_confusion"], skill_tags=["liquid_spacing"]),
            mcq("M5L1_C6", "A plaza is heated and the puck diameter on the screen stays constant. What lesson rule is being shown?", ["particles grow and shrink", "particle size stays constant while motion changes", "heating removes particles", "bulk properties belong to one particle"], 1, "The size rule is deliberate.", ["particle_size_heating_confusion"], skill_tags=["particle_size_rule"]),
        ],
        "diagnostic": [
            mcq("M5L1_D1", "Which statement best matches the particle model when matter is heated?", ["particles move more", "particles themselves get bigger", "each particle becomes wet", "all attractions are removed immediately"], 0, "Heating changes motion, not particle size or bulk properties.", ["particle_size_heating_confusion"], skill_tags=["particle_size_rule"]),
            mcq("M5L1_D2", "Which statement best names a bulk material property rather than a one-particle property?", ["the hardness of the whole solid block", "the mass of one particle", "the motion of one particle", "the existence of one particle"], 0, "Hardness belongs to the bulk material, not one isolated particle.", ["particle_bulk_property_confusion"], skill_tags=["bulk_vs_particle"]),
            mcq("M5L1_D3", "What does the Pulse Dial represent in the model?", ["particle size", "average liveliness of the pucks", "crowd color", "gravity"], 1, "Pulse Level is about average motion.", ["particle_motion_state_confusion"], skill_tags=["pulse_meaning"]),
            mcq("M5L1_D4", "A substance is heated but kept in the same state. Which change is most direct?", ["particles get larger", "particles move more vigorously", "particles lose all mass", "particles become wet"], 1, "Heating changes motion first, not size.", ["particle_size_heating_confusion"], skill_tags=["particle_size_rule"]),
            short("M5L1_D5", "Why can the same particles still make different states?", ["because their motion and attractions can balance differently", "because the balance between jiggle and grip can change", "because spacing and movement can change without changing particle size"], "Use balance, spacing, or motion language.", ["particle_motion_state_confusion"], acceptance_rules=acceptance_groups(["motion", "jiggle", "move"], ["attraction", "grip", "pull"], ["balance", "different", "spacing", "arrangement", "state"]), skill_tags=["state_from_balance"]),
            mcq("M5L1_D6", "Which description best fits a liquid in the particle model?", ["its particles stay close together and can change neighbors", "its particles are almost as far apart as in a gas", "its particles are fixed in place and motionless", "its particles become larger than solid particles"], 0, "Liquids stay close-packed but mobile.", ["liquid_spacing_confusion"], skill_tags=["liquid_spacing"]),
            mcq("M5L1_D7", "What stays fixed when the plaza is heated in this model?", ["the particle size", "the Pulse Level", "the spacing pattern", "the state necessarily"], 0, "This lesson protects the size rule explicitly.", ["particle_size_heating_confusion"], skill_tags=["particle_size_rule"]),
            mcq("M5L1_D8", "Which statement best fits the particle model?", ["one particle can be wet because the material is wet", "bulk properties come from many particles together", "a particle becomes solid when cold", "the same particle is larger in a gas"], 1, "Keep one particle separate from the whole crowd.", ["particle_bulk_property_confusion"], skill_tags=["bulk_vs_particle"]),
        ],
        "transfer": [
            mcq("M5L1_M1", "A metal bar and the same metal bar after heating are compared. Which statement is strongest?", ["its particles are bigger after heating", "its particles are the same size but move more", "its particles became a different substance", "its particles have become wet"], 1, "Heating changes motion, not particle size.", ["particle_size_heating_confusion"], skill_tags=["particle_size_rule"]),
            mcq("M5L1_M2", "Which correction is best for 'a water particle is wet'?", ["one particle can be wet if the liquid is wet", "wetness is a bulk property of many particles together", "wetness means particle size has changed", "water particles are tiny droplets"], 1, "Bulk material properties do not belong to one particle in isolation.", ["particle_bulk_property_confusion"], skill_tags=["bulk_vs_particle"]),
            short("M5L1_M3", "Why is a heated liquid still made of the same-size particles?", ["because heating changes motion and spacing rather than particle size", "because the particles stay the same size even when the liquid is heated", "because only the crowd pattern changes"], "Use same-size and motion/spacing language together.", ["particle_size_heating_confusion"], acceptance_rules=acceptance_groups(["same size", "stay the same size", "not bigger"], ["motion", "move", "jiggle", "spacing", "separation", "arrangement", "crowd pattern"]), skill_tags=["particle_size_rule"]),
            mcq("M5L1_M4", "A diagram shows close particles that can swap neighbors. Which state is being represented?", ["solid", "liquid", "gas", "vacuum"], 1, "Close and mobile together means liquid.", ["liquid_spacing_confusion"], skill_tags=["state_from_balance"]),
            mcq("M5L1_M5", "Which pair belongs together?", ["bigger particles and higher temperature", "same-size particles and greater motion", "wet particles and liquid state", "hard particles and solid state"], 1, "Temperature changes motion more directly than size.", ["particle_size_heating_confusion"], skill_tags=["pulse_meaning"]),
            mcq("M5L1_M6", "What explains a state change in the Pulse-Plaza best?", ["the pucks get larger", "the balance between jiggle and grip changes", "the pucks stop existing", "the crowd size must double"], 1, "State is a tug-of-war between motion and attraction.", ["particle_motion_state_confusion"], skill_tags=["state_from_balance"]),
            short("M5L1_M7", "Why is calling a particle 'hard' weak particle-model language?", ["because hardness is a bulk property of many particles together", "because one particle does not carry the whole material property", "because bulk properties emerge from many particles"], "Keep one-particle and whole-material language separate.", ["particle_bulk_property_confusion"], acceptance_rules=acceptance_groups(["bulk", "whole material", "many particles", "crowd"], ["hardness", "hard", "property", "emerge", "together", "not one particle"]), skill_tags=["bulk_vs_particle"]),
            mcq("M5L1_M8", "Which lesson rule blocks both 'particles get bigger' and 'liquid particles are wet'?", ["particle ideas must stay separate from crowd-level outcomes", "temperature and internal energy are the same", "deeper means denser", "pressure and force are the same"], 0, "One-particle claims and whole-crowd claims must not be merged.", ["particle_bulk_property_confusion", "particle_size_heating_confusion"], skill_tags=["bulk_vs_particle"]),
        ],
        "contract": contract(
            concept_targets=[
                "Particle size stays constant while motion and spacing can change",
                "Bulk properties do not belong to one isolated particle",
                "State comes from the balance between motion and attraction",
            ],
            core_concepts=[
                "Particles do not get bigger when heated.",
                "Heating changes particle motion and can change spacing patterns.",
                "Bulk material properties do not belong to one isolated particle.",
                "State depends on particle motion, spacing, and attraction together.",
            ],
            prerequisite_lessons=[],
            misconception_focus=[
                "particle_size_heating_confusion",
                "particle_bulk_property_confusion",
                "liquid_spacing_confusion",
                "particle_motion_state_confusion",
            ],
            formulas=[
                relation(
                    "Heating changes motion and spacing tendency, not particle size",
                    "The particle model protects size constancy while allowing motion and arrangement to change.",
                    ["qualitative rule"],
                    "Use when students are tempted to say particles grow or shrink during heating.",
                )
            ],
            representations=[
                representation("words", "States the particle rules before any diagram is interpreted."),
                representation("model", "Keeps the Pulse-Plaza balance between jiggle and grip visible."),
                representation("diagram", "Shows close, sliding, or drifting particle patterns without changing puck size."),
            ],
            analogy_map=pulse_plaza_map("the crowd is heated or the grip balance changes"),
            worked_examples=[
                worked("A learner says wax melts because each particle becomes larger. How should the model correct this?", ["Keep the size rule fixed first: the micro-pucks do not grow.", "Name what can change instead: motion, spacing pattern, and neighbor changes.", "Connect the new pattern to a change of state rather than a change of particle size."], "The particles stay the same size; the state changes because motion and arrangement change.", "The particle model changes the crowd pattern, not the size of each particle.", "This blocks the very common mistake that heating enlarges the particles themselves."),
                worked("A steel block is hard. Why is it stronger to say hardness belongs to the whole block rather than to one isolated particle?", ["Separate one particle from the whole material first.", "Keep one-particle properties to things like mass, motion, and position.", "Place hardness on the bulk solid because it comes from many particles arranged and interacting together."], "Hardness is a bulk property of the solid, not a property of one isolated particle.", "A single particle can have mass and motion, but hardness appears from many particles and their arrangement in the solid together.", "This keeps the particle model focused on bulk properties emerging from many particles rather than being copied onto one particle."),
                worked("A diagram shows close particles that can change neighbors without becoming far apart. Which state fits best?", ["Check spacing first: the particles are still close together.", "Then check motion: they can move around one another.", "Match that pair of features to the named state."], "The diagram represents a liquid.", "Liquids keep particles close but allow neighbor changes, unlike solids and gases.", "This keeps liquids from being described as if they already have gas-like large gaps."),
            ],
            visual_assets=[visual("m5-l1-particle-rules", "particle_model", "Micro-pucks stay the same size", "Shows that heating changes motion and spacing patterns without changing particle size.", "The same-size micro-pucks can be more lively or more spread out, but they do not grow.")],
            animation_assets=[animation("m5-l1-particle-rules-shift", "particle_model", "Heating without bigger particles", "Shows motion rising and spacing loosening while each micro-puck keeps the same size.")],
            simulation_contract={
                "asset_id": "m5_l1_particle_rules_lab",
                "concept": "particle_model",
                "baseline_case": "Start with a medium pulse and medium grip so the crowd is easy to inspect.",
                "focus_prompt": "Which changes belong to one particle, and which belong to the whole crowd pattern?",
                "controls": [
                    {"variable": "pulse_level", "label": "Pulse Dial", "why_it_matters": "Changes average jiggle without changing particle size."},
                    {"variable": "grip_level", "label": "Grip Dial", "why_it_matters": "Changes how strongly neighbors hold together."},
                    {"variable": "crowd_size", "label": "Crowd Size", "why_it_matters": "Keeps whole-plaza claims separate from one-particle claims."},
                ],
                "readouts": [
                    {"label": "State mode", "meaning": "Shows whether motion and grip give a locked, sliding, or drifting pattern."},
                    {"label": "Particle size", "meaning": "Stays fixed to prove that heating does not enlarge particles."},
                    {"label": "Neighbor mobility", "meaning": "Shows whether particles stay fixed or change neighbors."},
                ],
                "comparison_tasks": ["Increase pulse while keeping grip fixed and explain what changes.", "Hold pulse fixed and change grip to compare the crowd pattern."],
                "watch_for": "Students should explain changes through motion, spacing, and attraction rather than particle growth or one-particle bulk properties.",
                "takeaway": "Particle size stays fixed. Heating and state change belong to motion, spacing, and attraction patterns instead.",
            },
            reflection_prompts=["Why does the model insist that micro-pucks never get bigger?", "Why is 'one particle is wet' weaker than 'the liquid is wet'?"],
            mastery_skills=[
                "Reject particle-growth claims during heating",
                "Separate one-particle claims from bulk-material claims",
                "Describe state through motion spacing and attraction",
                "Identify liquid spacing correctly",
                "Use the Pulse-Plaza rules in new contexts",
            ],
            variation_plan={
                "diagnostic": "Rotate the opening check across particle-size, bulk-property, and liquid-spacing misconceptions so fresh attempts do not repeat one stem.",
                "concept_gate": "Retry the same idea through new diagrams and particle-language corrections rather than repeating the same wording.",
                "mastery": "Prefer unseen contexts that vary the mistaken statement, the state picture, and the particle-versus-bulk distinction before repeating any prior item.",
            },
            scaffold_support=scaffold(
                "The particle model changes motion, spacing, and attraction patterns, not the size of the particles themselves.",
                "Ask first whether the statement belongs to one particle or to the whole crowd. Then describe the state with spacing, movement, and attraction together.",
                "If heating changes the state pattern, what three things should you talk about before you mention size?",
                "Do not let bulk-material language like wet, hard, or bigger slide onto one isolated particle.",
                "The Pulse-Plaza starts by freezing particle size and forcing you to watch the tug-of-war between jiggle and grip instead.",
                "Why is keeping the puck size fixed such an important safety rail for the model?",
                extra_sections=[
                    extra_section("One-particle versus whole-crowd language", "A particle can have mass and motion, but bulk properties such as wetness or hardness belong to the whole material formed by many interacting particles."),
                    extra_section("State preview", "The three state patterns come from how motion competes with attraction. Later lessons will build Lock Mode, Slide Mode, and Drift Mode in detail."),
                ],
            ),
            visual_clarity_checks=visual_checks("particle-model"),
        ),
    }


def lesson_l2() -> Dict[str, Any]:
    return {
        "id": "M5_L2",
        "title": "Lock Mode and Slide Mode",
        "sim": {
            "lab_id": "m5_lock_slide_lab",
            "title": "Lock and slide builder",
            "description": "Build solid and liquid states by comparing close-packed particles that either stay in place or change neighbors.",
            "instructions": [
                "Create a lock pattern where particles stay in fixed positions and only jiggle.",
                "Then loosen the structure into a slide pattern where particles stay close but can swap neighbors.",
                "Keep spacing, motion, and attraction visible together in every explanation.",
            ],
            "outcomes": [
                "liquid_spacing_confusion",
                "particle_motion_state_confusion",
            ],
            "fields": ["pulse_level", "grip_level", "neighbor_swaps", "state_mode", "spacing_index"],
            "depth": "number of solid-versus-liquid comparisons explained using spacing, motion, and neighbor changes together",
        },
        "analogy_text": (
            "In Lock Mode, micro-pucks occupy set pads and only jiggle around them. In Slide Mode, the pucks still stay close, but the pads no longer trap them, "
            "so they can move around one another and trade neighbors while the crowd remains compact."
        ),
        "commitment_prompt": "Before naming the state, check both closeness and neighbor change.",
        "micro_prompts": [
            prompt_block("What stays the same between solids and liquids in the model?", "Keep their close spacing visible."),
            prompt_block("What changes between Lock Mode and Slide Mode?", "Use fixed positions versus neighbor swaps."),
            prompt_block("Why is a liquid not just halfway to a gas?", "Liquids stay close-packed rather than widely separated."),
        ],
        "inquiry": [
            prompt_block("Build a solid. What motion is allowed and what motion is not?", "Use vibration around fixed positions."),
            prompt_block("Now build a liquid. What changes while the particles remain close?", "Mention neighbor changes or flow past one another."),
            prompt_block("Compare a liquid with a gas. Which spacing clue keeps them apart?", "Liquids remain close; gases are far apart."),
        ],
        "recon_prompts": [
            "A solid has closely packed particles vibrating about fixed positions.",
            "A liquid has closely packed particles that can move around one another.",
            "Liquids are not modeled with huge gaps between particles.",
        ],
        "capsule_prompt": "Use spacing and neighbor mobility together so solids and liquids do not collapse into one vague crowd picture.",
        "capsule_checks": [
            mcq("M5L2_C1", "Which description matches a solid best?", ["close particles vibrating about fixed positions", "far-apart particles moving freely", "close particles rapidly changing neighbors everywhere", "particles with no motion at all"], 0, "The solid picture keeps closeness and fixed positions together.", ["particle_motion_state_confusion"], skill_tags=["solid_motion"]),
            mcq("M5L2_C2", "Which statement about a liquid is strongest?", ["its particles are far apart", "its particles stay close but can move around one another", "its particles stop moving", "its particles are larger than solid particles"], 1, "Liquid means close and mobile together.", ["liquid_spacing_confusion"], skill_tags=["liquid_motion"]),
            short("M5L2_C3", "Why is calling a liquid 'almost a gas' weak?", ["because liquid particles are still close together", "because liquids stay crowded even though the particles can move", "because liquids do not have gas-like huge gaps"], "Use close-together language clearly.", ["liquid_spacing_confusion"], acceptance_rules=acceptance_groups(["liquid", "liquids"], ["close", "crowded", "near", "packed", "still close"], ["not gas", "not huge gaps", "do not have huge gaps", "not far apart"]), skill_tags=["liquid_spacing"]),
            mcq("M5L2_C4", "What is the clearest sign that Slide Mode is not Lock Mode?", ["the particles gain mass", "the particles can change neighbors", "the particles become bigger", "the particles lose all attraction"], 1, "Neighbor swapping is the key mobility change.", ["particle_motion_state_confusion"], skill_tags=["neighbor_change"]),
            mcq("M5L2_C5", "Which pair stays most similar between solids and liquids in the simple model?", ["closeness and attraction", "color and size", "far spacing and free drift", "self-propulsion and growth"], 0, "Both states keep particles close together.", ["liquid_spacing_confusion"], skill_tags=["solid_liquid_compare"]),
            mcq("M5L2_C6", "A crowd stays close but records 18 neighbor swaps in one interval. Which state fits better?", ["solid", "liquid", "gas", "vacuum"], 1, "Close spacing plus neighbor changes points to liquid.", ["particle_motion_state_confusion"], skill_tags=["neighbor_change"]),
        ],
        "diagnostic": [
            mcq("M5L2_D1", "Which sentence about a solid is correct?", ["Particles are far apart and still", "Particles are close and vibrate around fixed positions", "Particles are close and move freely between collisions", "Particles are wet"], 1, "Solids keep fixed positions but still jiggle.", ["particle_motion_state_confusion"], skill_tags=["solid_motion"]),
            mcq("M5L2_D2", "Which sentence best distinguishes Slide Mode from Drift Mode?", ["Particles stay close but can change neighbors in Slide Mode", "Particles are almost as far apart as in a gas in Slide Mode", "Particles are fixed in place in Slide Mode", "Particles become larger in Slide Mode"], 0, "Slide Mode stays close-packed while Drift Mode spreads out.", ["liquid_spacing_confusion"], skill_tags=["liquid_spacing"]),
            mcq("M5L2_D3", "What is the main motion difference between a solid and a liquid?", ["the liquid particles are larger", "the liquid particles can move past one another", "the solid particles have no motion", "the liquid particles have no attraction"], 1, "Mobility changes while closeness stays.", ["particle_motion_state_confusion"], skill_tags=["liquid_motion"]),
            mcq("M5L2_D4", "A diagram shows close particles with no long jumps but many neighbor swaps. Which state is it?", ["solid", "liquid", "gas", "plasma"], 1, "Close spacing plus neighbor changes means liquid.", ["particle_motion_state_confusion"], skill_tags=["neighbor_change"]),
            short("M5L2_D5", "Why is a liquid still modeled with close particles?", ["because liquid particles remain close together even though they move", "because a liquid is not a gas with huge gaps", "because sliding does not mean far apart"], "Use close-spacing language.", ["liquid_spacing_confusion"], acceptance_rules=acceptance_groups(["close", "crowded", "packed", "near"], ["move", "slide", "change neighbors"], ["not gas", "not huge gaps", "not far apart"]), skill_tags=["liquid_spacing"]),
            mcq("M5L2_D6", "Which readout best supports Lock Mode?", ["spacing close and neighbor swaps zero", "spacing far and collisions high", "spacing close and neighbor swaps very high", "spacing random and no attraction"], 0, "A solid keeps close spacing and fixed positions.", ["particle_motion_state_confusion"], skill_tags=["solid_motion"]),
            mcq("M5L2_D7", "Which readout best supports Slide Mode?", ["spacing close and neighbor swaps above zero", "spacing far and free drift", "zero motion and fixed size only", "particle growth under heating"], 0, "A liquid stays close but mobile.", ["particle_motion_state_confusion"], skill_tags=["neighbor_change"]),
            mcq("M5L2_D8", "What does Slide Mode teach most clearly?", ["liquids have huge empty gaps", "liquids keep particles close while allowing flow", "liquids are made of bigger particles", "liquids have no attraction"], 1, "Flow does not require gas-like spacing.", ["liquid_spacing_confusion"], skill_tags=["liquid_motion"]),
        ],
        "transfer": [
            mcq("M5L2_M1", "A material changes shape to fit its container but keeps nearly the same volume. Which particle picture fits?", ["far-apart drifting particles", "close particles moving around one another", "fixed-position particles only", "particles growing with heat"], 1, "That is the liquid picture.", ["liquid_spacing_confusion"], skill_tags=["liquid_motion"]),
            mcq("M5L2_M2", "Which statement best compares solids and liquids?", ["Only solids have close particles", "Both have close particles, but only liquids let neighbors change readily", "Liquids have no attractions", "Solids have no motion"], 1, "Keep closeness and mobility separate.", ["particle_motion_state_confusion"], skill_tags=["solid_liquid_compare"]),
            short("M5L2_M3", "Why can a liquid flow while a solid keeps its shape?", ["because liquid particles can move around one another while solid particles stay near fixed positions", "because liquid particles change neighbors but solid particles mainly vibrate in place", "because liquid particles are mobile while solids are locked"], "Use mobility and fixed-position language.", ["particle_motion_state_confusion"], acceptance_rules=acceptance_groups(["liquid", "liquids"], ["move around", "change neighbors", "flow", "mobile", "slide"], ["solid", "solids"], ["fixed", "vibrate", "locked", "in place"]), skill_tags=["solid_liquid_compare"]),
            mcq("M5L2_M4", "Two diagrams are both close-packed. One shows 0 neighbor swaps in 10 s; the other shows 14 swaps in 10 s. Which is the liquid?", ["the 0-swap diagram", "the 14-swap diagram", "both are solids", "neither can be liquid"], 1, "Neighbor mobility is the key difference.", ["particle_motion_state_confusion"], skill_tags=["neighbor_change"]),
            mcq("M5L2_M5", "Which mistake should you reject when describing a liquid?", ["Its particles remain close", "Its particles move around one another", "Its particles are widely separated like a gas", "Its particles still attract one another"], 2, "This is the classic liquid-spacing misconception.", ["liquid_spacing_confusion"], skill_tags=["liquid_spacing"]),
            short("M5L2_M6", "What pair of ideas must stay together to identify a liquid correctly?", ["close spacing and particle mobility", "close together and able to change neighbors", "crowded particles and flow"], "Use one spacing clue and one motion clue.", ["liquid_spacing_confusion", "particle_motion_state_confusion"], acceptance_rules=acceptance_groups(["close", "crowded", "packed"], ["move", "flow", "slide", "change neighbors", "mobile"]), skill_tags=["liquid_motion"]),
            mcq("M5L2_M7", "Which claim about a solid is strongest?", ["Its particles are motionless", "Its particles vibrate around fixed positions", "Its particles are far apart", "Its particles are bigger than liquid particles"], 1, "Solids still have motion.", ["particle_motion_state_confusion"], skill_tags=["solid_motion"]),
            mcq("M5L2_M8", "Which state description uses the best particle language?", ["liquid = medium gaps and no attractions", "solid = close particles with fixed positions; liquid = close particles with mobility", "gas = same spacing as liquid but faster", "solid = particles glued permanently"], 1, "Use spacing, motion, and attraction accurately.", ["liquid_spacing_confusion", "particle_motion_state_confusion"], skill_tags=["solid_liquid_compare"]),
        ],
        "contract": contract(
            concept_targets=[
                "Describe solids and liquids using particle spacing and motion",
                "Keep liquids close-packed rather than gas-like",
                "Use neighbor change to separate locked and sliding states",
            ],
            core_concepts=[
                "Solids have closely packed particles vibrating about fixed positions.",
                "Liquids have closely packed particles that can move around one another.",
                "Liquid particles are still close together rather than gas-like.",
                "State descriptions must combine spacing, motion, and attraction.",
            ],
            prerequisite_lessons=["M5_L1"],
            misconception_focus=["liquid_spacing_confusion", "particle_motion_state_confusion"],
            formulas=[relation("solid: close + fixed positions; liquid: close + neighbor change", "The key difference between a solid and a liquid is mobility while closeness remains.", ["qualitative rule"], "Use when students confuse liquids with gases or solids with motionless particles.")],
            representations=[
                representation("words", "States the solid-liquid particle rules plainly."),
                representation("model", "Shows Lock Mode and Slide Mode as different balances of jiggle and grip."),
                representation("table", "Compares spacing, motion, and neighbor change side by side."),
            ],
            analogy_map=pulse_plaza_map("the crowd changes between locked and sliding patterns"),
            worked_examples=[
                worked("A learner says liquid particles must be far apart because liquids flow. How should you respond?", ["Keep the flowing observation but question the spacing claim.", "State that liquid particles remain close while gaining neighbor mobility.", "Use the contrast with gas spacing to finish the correction."], "Liquids flow because their close particles can move around one another, not because they are far apart.", "Flow comes from mobility, while close spacing is still part of the liquid model.", "This is the central correction to the 'liquid equals medium gap' misconception."),
                worked("A diagram shows close particles and zero neighbor swaps over an interval. Which state fits best?", ["Read the spacing first: the particles are close.", "Then read the mobility: no neighbor swaps means fixed positions.", "Match that pattern to the state name."], "The diagram best represents a solid.", "A solid keeps close particles with motion limited to vibration about fixed positions.", "This helps students use more than one clue at once rather than guessing from one feature."),
                worked("Two diagrams are both close-packed. One shows 2 swaps in 10 s and the other 18 swaps in 10 s. Which is more liquid-like?", ["Notice that both diagrams are not gas-like because spacing is still close.", "Use the higher neighbor-swap count as evidence of greater mobility.", "Choose the more slide-like case."], "The 18-swap case is more liquid-like.", "Higher neighbor mobility while staying close is the key sign of Slide Mode.", "This anchors the idea that liquids differ from solids more in mobility than in spacing."),
            ],
            visual_assets=[visual("m5-l2-lock-slide", "states_of_matter", "Lock and Slide board", "Compares close-packed solids and liquids using fixed positions versus neighbor changes.", "Both states stay close-packed, but only the liquid picture shows ready neighbor changes.")],
            animation_assets=[animation("m5-l2-lock-slide-shift", "states_of_matter", "From lock to slide", "Shows particles staying close while the pattern loosens from fixed pads into neighbor-changing flow.")],
            simulation_contract={
                "asset_id": "m5_l2_lock_slide_lab",
                "concept": "states_of_matter",
                "baseline_case": "Start with a close-packed crowd under strong grip and moderate pulse.",
                "focus_prompt": "Which clues show a solid, and which clues show a liquid, when the particles stay close in both?",
                "controls": [
                    {"variable": "pulse_level", "label": "Pulse Dial", "why_it_matters": "Changes how strongly particles jiggle against the grip links."},
                    {"variable": "grip_level", "label": "Grip Dial", "why_it_matters": "Keeps or loosens the locked arrangement."},
                    {"variable": "neighbor_swap_window", "label": "Observation interval", "why_it_matters": "Makes fixed positions and swapping behavior easier to compare."},
                ],
                "readouts": [
                    {"label": "State mode", "meaning": "Summarizes whether the crowd behaves like Lock Mode or Slide Mode."},
                    {"label": "Neighbor swaps", "meaning": "Counts how often particles change neighbors over the interval."},
                    {"label": "Spacing index", "meaning": "Shows that both states remain close-packed even though their mobility differs."},
                ],
                "comparison_tasks": ["Build a solid and then a liquid without making the liquid gas-like.", "Hold spacing close and compare zero versus many neighbor swaps."],
                "watch_for": "Students should not describe liquids with huge gaps or solids as motionless.",
                "takeaway": "Solids and liquids both keep particles close, but only liquids let them move around one another readily.",
            },
            reflection_prompts=["Why is 'liquid particles are far apart' such a damaging shortcut?", "What two clues together identify a liquid better than one clue alone?"],
            mastery_skills=[
                "Describe solids accurately with particle language",
                "Describe liquids accurately with particle language",
                "Reject liquid-spacing misconceptions",
                "Use neighbor mobility as evidence",
                "Compare solids and liquids without collapsing them together",
            ],
            variation_plan={
                "diagnostic": "Rotate the opening items across diagrams, motion statements, and liquid-spacing claims so attempts feel new.",
                "concept_gate": "Retry with changed representations such as neighbor-swap counts, still images, and verbal corrections.",
                "mastery": "Prefer unseen same-spacing comparisons, solid-liquid contrasts, and new particle descriptions before repeating any prior stem.",
            },
            scaffold_support=scaffold(
                "Solids and liquids both keep particles close together, but a liquid differs because its particles can move around one another and change neighbors.",
                "Read spacing first, then read mobility. Close plus fixed positions gives a solid; close plus ready neighbor changes gives a liquid.",
                "If two states are both close-packed, what motion clue will help you separate them?",
                "Do not use flow as proof that the particles are far apart. Liquids flow while still staying close-packed.",
                "Lock Mode and Slide Mode are useful because they change neighbor freedom without pretending liquids need gas-like spacing.",
                "Why does the model keep the solid and liquid crowds similarly crowded even while their behaviors differ?",
                extra_sections=[
                    extra_section("Neighbor swaps matter", "A count of neighbor changes is a clean clue because it keeps mobility visible without changing the spacing story."),
                    extra_section("Flow is not the same as large gaps", "A liquid can flow because particles can move around one another, not because the crowd has opened into gas-like emptiness."),
                ],
            ),
            visual_clarity_checks=visual_checks("state-mode"),
        ),
    }


def lesson_l3() -> Dict[str, Any]:
    return {
        "id": "M5_L3",
        "title": "Drift Mode and Brownian Motion",
        "sim": {
            "lab_id": "m5_drift_brownian_lab",
            "title": "Drift and jostle lab",
            "description": "Use a gas-like plaza and a Wander Pebble to connect free particle motion with Brownian evidence.",
            "instructions": [
                "Increase pulse and weaken grip until the crowd reaches Drift Mode.",
                "Switch on the Wander Pebble and watch its jagged path.",
                "Explain every zigzag as random collisions from invisible surrounding particles.",
            ],
            "outcomes": [
                "particle_motion_state_confusion",
                "brownian_self_motion_confusion",
            ],
            "fields": ["pulse_level", "grip_level", "wander_pebble", "collision_rate", "state_mode"],
            "depth": "number of gas-state and Brownian explanations that use free motion, spacing, and random collisions together",
        },
        "analogy_text": (
            "Drift Mode is the gas picture: micro-pucks are far apart and move freely between collisions. "
            "When the Wander Pebble is dropped into that restless crowd, it jitters in a shaky path because the unseen pucks strike it unevenly from changing directions."
        ),
        "commitment_prompt": "Before you answer, separate the motion of the invisible pucks from the motion of the visible Wander Pebble.",
        "micro_prompts": [
            prompt_block("What makes Drift Mode different from Slide Mode?", "Use far spacing and free motion between collisions."),
            prompt_block("Why does the Wander Pebble zigzag?", "Use uneven random collisions from surrounding particles."),
            prompt_block("What does Brownian motion count as evidence for?", "It is evidence that unseen particles are moving randomly."),
        ],
        "inquiry": [
            prompt_block("Lower the grip and raise the pulse until the crowd drifts freely. What spacing and motion clues now identify a gas?", "Use far-apart plus free motion between collisions."),
            prompt_block("Turn on the Wander Pebble. Why does its path keep changing direction?", "Use random unequal hits from surrounding pucks."),
            prompt_block("Compare the Wander Pebble at low pulse and high pulse. What changes in the jostle pattern?", "Stronger surrounding motion gives more vigorous random jostling."),
        ],
        "recon_prompts": [
            "A gas is modeled as particles far apart that move freely except during collisions.",
            "Brownian motion is the random movement of a visible particle due to collisions with surrounding unseen particles.",
            "The Wander Pebble is not self-propelled; its path is caused by the surrounding crowd.",
        ],
        "capsule_prompt": "Use gas-spacing and collision language together so Brownian motion stays evidence of unseen particles rather than a self-powered motion story.",
        "capsule_checks": [
            mcq("M5L3_C1", "Which statement best describes Drift Mode?", ["Particles are far apart and move freely between collisions", "Particles stay close and fixed", "Particles are close and only swap neighbors", "Particles become larger"], 0, "Gas mode needs far spacing and free motion together.", ["particle_motion_state_confusion"], skill_tags=["gas_motion"]),
            mcq("M5L3_C2", "Why does the Wander Pebble move in a jagged path?", ["Because it is alive", "Because random collisions from surrounding particles keep changing the net push on it", "Because gravity changes every second", "Because the pebble makes its own energy"], 1, "Brownian motion is caused by uneven molecular collisions.", ["brownian_self_motion_confusion"], skill_tags=["brownian_cause"]),
            short("M5L3_C3", "Why is calling the Wander Pebble 'self-powered' weak?", ["because the surrounding particles are pushing it randomly", "because its zigzag comes from unequal collisions with surrounding particles", "because the motion is caused by random jostles from the invisible crowd"], "Use collision language rather than self-motion language.", ["brownian_self_motion_confusion"], acceptance_rules=acceptance_groups(["collision", "jostle", "hit", "push"], ["random", "unequal", "surrounding", "invisible", "crowd", "particles"]), skill_tags=["brownian_cause"]),
            mcq("M5L3_C4", "Which clue most strongly separates a gas from a liquid in the model?", ["The gas particles are larger", "The gas particles are far apart and mostly move independently", "The gas particles are wet", "The gas particles stop colliding"], 1, "Gas spacing and freer motion are the key clues.", ["particle_motion_state_confusion"], skill_tags=["gas_vs_liquid"]),
            short("M5L3_C5", "Why is Brownian motion evidence for unseen particles?", ["because the visible pebble is being hit by invisible particles", "because the random jitter shows surrounding particles are moving and colliding", "because something unseen must keep knocking the pebble from different sides"], "Use visible-particle and unseen-collision language together.", ["brownian_self_motion_confusion"], acceptance_rules=acceptance_groups(["visible", "pebble", "particle"], ["invisible", "unseen", "surrounding"], ["hit", "collide", "knock", "jostle", "push"]), skill_tags=["brownian_evidence"]),
            mcq("M5L3_C6", "At higher Pulse Level in Drift Mode, the Wander Pebble should usually...", ["jiggle more vigorously", "stop moving", "turn into a liquid", "become larger"], 0, "Greater surrounding motion gives more vigorous jostling.", ["brownian_self_motion_confusion"], skill_tags=["brownian_pulse_effect"]),
        ],
        "diagnostic": [
            mcq("M5L3_D1", "Which state description is strongest for a gas?", ["Particles are far apart and move freely except during collisions", "Particles are close together and fixed", "Particles are close and change neighbors", "Particles are larger than in a liquid"], 0, "Use the standard gas particle picture.", ["particle_motion_state_confusion"], skill_tags=["gas_motion"]),
            mcq("M5L3_D2", "Which statement correctly explains Brownian motion?", ["It is random visible zigzag motion caused by collisions with surrounding molecules", "It proves the visible particle is self-propelled", "It means the visible particle is growing and shrinking", "It is a steady one-way drift chosen by the particle"], 0, "Brownian motion is caused by uneven surrounding collisions.", ["brownian_self_motion_confusion"], skill_tags=["brownian_cause"]),
            mcq("M5L3_D3", "What happens between most gas-particle collisions?", ["Particles move freely through the space between them", "Particles stay in fixed positions", "Particles become bigger", "Particles stop moving"], 0, "Free motion between collisions is part of the gas model.", ["particle_motion_state_confusion"], skill_tags=["gas_motion"]),
            short("M5L3_D4", "Why does the Wander Pebble not move in a straight line?", ["because the surrounding particle collisions are random and unequal", "because hits from different sides keep changing its motion", "because random jostles keep changing the net push on it"], "Use random-collision language.", ["brownian_self_motion_confusion"], acceptance_rules=acceptance_groups(["random", "unequal", "different sides", "changing"], ["collision", "jostle", "hit", "push"]), skill_tags=["brownian_cause"]),
            mcq("M5L3_D5", "Which pair belongs together?", ["Gas: close-packed and fixed", "Gas: far apart and drifting freely", "Liquid: far apart and free between collisions", "Solid: far apart and colliding"], 1, "Only the gas picture uses far spacing and free drift together.", ["particle_motion_state_confusion"], skill_tags=["gas_vs_liquid"]),
            mcq("M5L3_D6", "What does Brownian motion mainly make visible?", ["Random molecular collisions that we cannot see directly", "That particles grow when heated", "That liquids have huge gaps", "That pressure and force are the same"], 0, "It is evidence of unseen particle motion.", ["brownian_self_motion_confusion"], skill_tags=["brownian_evidence"]),
            mcq("M5L3_D7", "If the surrounding gas becomes more lively, the Wander Pebble's path should become...", ["more strongly jittery", "perfectly straight", "motionless", "larger"], 0, "More energetic surrounding particles give stronger random jostling.", ["brownian_self_motion_confusion"], skill_tags=["brownian_pulse_effect"]),
            short("M5L3_D8", "Why is Drift Mode not just 'very loose liquid'?", ["because gas particles are far apart and move freely between collisions", "because a gas has much larger spacing than a liquid", "because the gas picture keeps particles mostly independent except when they collide"], "Use spacing plus free-motion language.", ["particle_motion_state_confusion"], acceptance_rules=acceptance_groups(["far apart", "large spacing", "far spacing", "spread out"], ["free", "independent", "between collisions", "move freely", "collide"]), skill_tags=["gas_vs_liquid"]),
        ],
        "transfer": [
            mcq("M5L3_M1", "Smoke particles under a microscope jitter randomly. What is the best explanation?", ["They are being hit unevenly by unseen air molecules", "They are alive", "They are moving toward heat by choice", "They are changing size"], 0, "Brownian motion is due to random collisions.", ["brownian_self_motion_confusion"], skill_tags=["brownian_evidence"]),
            mcq("M5L3_M2", "Which correction best answers 'Brownian particles move because they contain energy of their own'?", ["The motion is caused by surrounding particles colliding with them", "The visible particle is a tiny engine", "The particle is getting bigger", "The microscope makes it move"], 0, "Keep the cause outside the visible particle.", ["brownian_self_motion_confusion"], skill_tags=["brownian_cause"]),
            short("M5L3_M3", "Why is a gas described as mostly free motion between collisions?", ["because the particles are far apart and only interact strongly when they collide", "because gas particles travel through the gaps between collisions", "because the gas crowd is spread out enough for freer motion"], "Use far-spacing and collision language together.", ["particle_motion_state_confusion"], acceptance_rules=acceptance_groups(["far apart", "spread out", "gaps", "spacing"], ["collide", "collision", "between collisions", "free motion", "move freely"]), skill_tags=["gas_motion"]),
            mcq("M5L3_M4", "A visible pollen grain jitters more strongly when the air around it is warmer. What is the strongest reason?", ["Surrounding molecules are moving more vigorously and striking it more unevenly", "The pollen grain becomes self-powered", "The pollen grain grows", "Gravity becomes random"], 0, "Warmer surroundings mean stronger random collisions.", ["brownian_self_motion_confusion"], skill_tags=["brownian_pulse_effect"]),
            mcq("M5L3_M5", "Which state comparison is strongest?", ["A liquid and gas are both far apart", "A liquid is close-packed; a gas is far apart and freer between collisions", "A solid and gas are both close-packed", "A gas has no collisions"], 1, "Use spacing and collision language together.", ["particle_motion_state_confusion"], skill_tags=["gas_vs_liquid"]),
            short("M5L3_M6", "What does Brownian motion let us infer about matter?", ["that tiny surrounding particles are moving randomly and colliding", "that invisible particles exist and keep jostling visible ones", "that molecular motion can be inferred from the zigzag of a larger particle"], "Answer in terms of unseen particle motion and collisions.", ["brownian_self_motion_confusion"], acceptance_rules=acceptance_groups(["invisible", "unseen", "tiny", "molecular", "surrounding"], ["move", "motion", "random"], ["collision", "jostle", "hit", "knock"]), skill_tags=["brownian_evidence"]),
            mcq("M5L3_M7", "A diagram shows particles far apart with long straight segments between occasional collisions. Which state is it?", ["solid", "liquid", "gas", "liquid becoming solid"], 2, "That is the standard gas picture.", ["particle_motion_state_confusion"], skill_tags=["gas_motion"]),
            mcq("M5L3_M8", "Which statement keeps the lesson hierarchy strongest?", ["Brownian motion is a visible clue to invisible particle collisions", "Brownian particles move because they are alive", "A gas is just a liquid with bigger particles", "Particles become wet when a liquid evaporates"], 0, "The best answer connects the evidence to the particle model.", ["brownian_self_motion_confusion", "particle_motion_state_confusion"], skill_tags=["brownian_evidence"]),
        ],
        "contract": contract(
            concept_targets=[
                "Describe gases using spacing motion and collisions",
                "Explain Brownian motion as random jostling from unseen particles",
                "Use Brownian motion as evidence for constant particle motion",
            ],
            core_concepts=[
                "Gases have particles far apart that move freely except during collisions.",
                "Brownian motion is the random movement of a visible particle due to collisions with surrounding invisible particles.",
                "The visible Brownian particle is not self-propelled.",
                "Stronger surrounding particle motion gives more vigorous Brownian jostling.",
            ],
            prerequisite_lessons=["M5_L1", "M5_L2"],
            misconception_focus=["particle_motion_state_confusion", "brownian_self_motion_confusion"],
            formulas=[
                relation("gas: far apart + free motion between collisions", "The gas model combines large spacing with freer motion and intermittent collisions.", ["qualitative rule"], "Use when comparing gases with solids or liquids."),
                relation("Brownian motion = visible jitter from uneven surrounding collisions", "The visible particle changes motion because surrounding invisible particles strike it unevenly.", ["qualitative rule"], "Use when explaining Brownian motion as evidence for molecular motion."),
            ],
            representations=[
                representation("words", "States the gas and Brownian rules plainly."),
                representation("model", "Uses Drift Mode and the Wander Pebble to keep invisible collisions visible through their effects."),
                representation("diagram", "Shows far spacing, free motion, and the jagged Brownian path."),
            ],
            analogy_map=pulse_plaza_map("the crowd drifts freely and a Wander Pebble is dropped into it"),
            worked_examples=[
                worked("A learner says smoke particles under a microscope move because they are alive. How should you answer?", ["Reject the self-powered idea first.", "Name the invisible surrounding particles as the cause of the changing pushes.", "Connect the visible zigzag to random unequal collisions from those unseen particles."], "The visible smoke particle jitters because surrounding molecules strike it unevenly, not because it is alive.", "Brownian motion is caused by collisions from surrounding particles, so the visible particle is evidence of unseen motion rather than a tiny engine.", "This turns Brownian motion into evidence for the particle model rather than a misleading self-motion story."),
                worked("A diagram shows particles far apart with long straight paths and occasional collisions. Which state is shown?", ["Read the spacing first: the particles are far apart.", "Then read the motion: long free paths interrupted by collisions.", "Match that pair of clues to the state name."], "The diagram represents a gas.", "A gas keeps particles far apart and mostly independent between collisions.", "This keeps gases from being described as just 'faster liquids'."),
                worked("A Wander Pebble jitters much more strongly after the Pulse Dial is raised. What is the best explanation?", ["Keep the visible particle the same size and identity.", "Change the surrounding crowd instead: higher pulse means more vigorous unseen motion.", "Link the stronger random hits to the stronger zigzag path."], "The surrounding particles are moving more vigorously and jostle the Wander Pebble more strongly.", "Raising the pulse changes the surrounding collision pattern, not the nature of the visible pebble.", "This connects Brownian motion to the motion of the surrounding invisible particles."),
            ],
            visual_assets=[visual("m5-l3-brownian-pebble", "brownian_motion", "Drift Mode and Wander Pebble", "Shows a gas-like plaza and the jagged path of a visible pebble struck by random collisions.", "The jagged Wander Pebble path is caused by uneven hits from the surrounding drifting micro-pucks.")],
            animation_assets=[animation("m5-l3-brownian-pebble-shift", "brownian_motion", "Random jostles in Drift Mode", "Shows the Wander Pebble tracing a shaky zigzag because surrounding pucks keep striking it from changing directions.")],
            simulation_contract={
                "asset_id": "m5_l3_drift_brownian_lab",
                "concept": "brownian_motion",
                "baseline_case": "Start with a high-pulse, weak-grip crowd so Drift Mode is visible before the Wander Pebble is added.",
                "focus_prompt": "Which clues show a gas, and how do the invisible collisions make the visible Wander Pebble move?",
                "controls": [
                    {"variable": "pulse_level", "label": "Pulse Dial", "why_it_matters": "Changes how vigorously surrounding particles move."},
                    {"variable": "grip_level", "label": "Grip Dial", "why_it_matters": "Keeps the crowd in or out of Drift Mode."},
                    {"variable": "wander_pebble", "label": "Wander Pebble toggle", "why_it_matters": "Makes the evidence of unseen collisions visible."},
                ],
                "readouts": [
                    {"label": "State mode", "meaning": "Shows when the plaza has truly reached Drift Mode."},
                    {"label": "Collision rate", "meaning": "Shows how often the invisible crowd is jostling the visible pebble."},
                    {"label": "Brownian path spread", "meaning": "Shows how vigorous the random visible jitter has become."},
                ],
                "comparison_tasks": ["Compare the Wander Pebble path at low and high Pulse Level.", "Compare a drifting crowd with and without the Wander Pebble visible."],
                "watch_for": "Students should explain the visible motion through invisible surrounding collisions rather than through self-propulsion.",
                "takeaway": "Brownian motion is visible evidence of invisible random particle collisions in a gas-like crowd.",
            },
            reflection_prompts=["Why does Brownian motion count as evidence for invisible particle motion?", "Why is a gas not just 'a liquid with extra speed'?"],
            mastery_skills=[
                "Describe gases accurately with particle language",
                "Explain Brownian motion causally",
                "Use Brownian motion as evidence",
                "Separate visible and invisible particle roles",
                "Compare gases with liquids without collapsing them together",
            ],
            variation_plan={
                "diagnostic": "Rotate between gas-state descriptions, Brownian evidence, and self-motion misconceptions so fresh attempts feel genuinely different.",
                "concept_gate": "Retry the idea through new diagrams, microscope contexts, and cause-language corrections rather than repeating one stem.",
                "mastery": "Prefer unseen gas-versus-liquid contrasts and new Brownian evidence contexts before repeating any prior question.",
            },
            scaffold_support=scaffold(
                "A gas is a crowd of far-apart particles moving freely between collisions, and Brownian motion is the visible jitter of a larger particle caused by those unseen collisions.",
                "Read the gas picture through spacing and collisions first. Then explain the Wander Pebble by asking which surrounding hits are unequal at that moment.",
                "Why does the visible Brownian path tell you something about particles you cannot directly see?",
                "Do not describe the Brownian particle as self-powered. The surrounding micro-pucks are doing the jostling.",
                "The Wander Pebble is useful because it turns invisible random collisions into a visible shaky path without pretending the larger particle causes its own motion.",
                "What remains hidden in the model, and what becomes visible through the Wander Pebble trace?",
                extra_sections=[
                    extra_section("Free paths matter", "Gas particles are not fixed and not close-packed. They move through larger gaps and only interact strongly during collisions."),
                    extra_section("Evidence through effects", "Brownian motion is powerful because it shows invisible molecular activity through the motion of a visible particle."),
                ],
            ),
            visual_clarity_checks=visual_checks("brownian-motion"),
        ),
    }


def lesson_l4() -> Dict[str, Any]:
    return {
        "id": "M5_L4",
        "title": "Pulse Level and Temperature",
        "sim": {
            "lab_id": "m5_pulse_temperature_lab",
            "title": "Pulse level comparer",
            "description": "Compare small and large plazas at the same Pulse Level so temperature stays an average particle-motion idea rather than a whole-system total.",
            "instructions": [
                "Set one Pulse Level and compare two plazas with different crowd sizes.",
                "Keep the pulse equal while you change the number of micro-pucks.",
                "Explain what stays the same and what does not when the average jiggle is matched.",
            ],
            "outcomes": [
                "temperature_internal_energy_confusion",
                "same_temperature_same_internal_energy_confusion",
            ],
            "fields": ["pulse_level", "crowd_a", "crowd_b", "average_jiggle", "plaza_store_proxy"],
            "depth": "number of same-pulse comparisons explained as average motion rather than total whole-system energy",
        },
        "analogy_text": (
            "Pulse Level is the average liveliness of the micro-pucks, not the whole energy budget of the entire plaza. "
            "That means a small plaza and a large plaza can share the same Pulse Level even though the larger crowd contains more moving particles overall."
        ),
        "commitment_prompt": "Before you answer, ask whether the question is about one typical puck or about the whole plaza.",
        "micro_prompts": [
            prompt_block("What does Pulse Level tell you?", "Use average particle liveliness language."),
            prompt_block("Can two plazas have the same Pulse Level with different crowd sizes?", "Yes - Pulse Level is an average, not a total."),
            prompt_block("Why is temperature not the same as total energy in the plaza?", "Average and total answer different questions."),
        ],
        "inquiry": [
            prompt_block("Hold the Pulse Dial fixed and increase the crowd size. Which reading is meant to stay the same?", "The average motion story stays the same."),
            prompt_block("Now compare a smaller and larger plaza with the same pulse. What whole-system difference still remains?", "There are more moving particles in the larger crowd."),
            prompt_block("Explain why the same Pulse Level does not automatically mean the same Plaza Store.", "Average motion is not the same as total system energy."),
        ],
        "recon_prompts": [
            "Temperature is modeled here as the average particle-motion level.",
            "Pulse Level answers a typical-particle question rather than a whole-system total-energy question.",
            "Two systems can share the same Pulse Level and still differ in total energy content.",
        ],
        "capsule_prompt": "Keep temperature as an average so it does not collapse into total internal-energy language too early.",
        "capsule_checks": [
            mcq("M5L4_C1", "What does Pulse Level represent in this lesson?", ["The average particle liveliness", "The total energy of the whole plaza", "The size of each particle", "The color of the plaza"], 0, "Pulse Level is an average-particle question.", ["temperature_internal_energy_confusion"], skill_tags=["temperature_average"]),
            mcq("M5L4_C2", "Two plazas have the same Pulse Level but different crowd sizes. Which claim is strongest?", ["They must have the same total energy", "They have the same average particle motion", "The larger plaza must be hotter", "The smaller plaza must contain larger particles"], 1, "Same pulse means same average motion, not necessarily the same total store.", ["same_temperature_same_internal_energy_confusion"], skill_tags=["same_temp_average"]),
            short("M5L4_C3", "Why is Pulse Level called an average?", ["because it describes the average motion of a typical particle", "because it tells how lively the particles are on average", "because it is about one typical puck rather than the whole total"], "Use average-particle language.", ["temperature_internal_energy_confusion"], acceptance_rules=acceptance_groups(["average", "typical"], ["particle", "puck"], ["motion", "jiggle", "lively", "kinetic"]), skill_tags=["temperature_average"]),
            mcq("M5L4_C4", "If two plazas are at the same Pulse Level, which statement must be true?", ["Their particles are the same size", "Their average particle motion is the same", "Their total energy is the same", "Their crowd size is the same"], 1, "Same temperature here means same average particle motion.", ["same_temperature_same_internal_energy_confusion"], skill_tags=["same_temp_average"]),
            mcq("M5L4_C5", "Which question is a temperature question?", ["How lively is one typical puck?", "How much total motion-and-link energy is in the whole plaza?", "How many pucks are in the plaza?", "How many links are broken in total?"], 0, "Temperature asks an average-particle question.", ["temperature_internal_energy_confusion"], skill_tags=["temperature_question"]),
            short("M5L4_C6", "Why can a larger plaza share the same Pulse Level as a smaller plaza?", ["because pulse level tracks average particle motion not crowd size", "because the average jiggle can match even when the number of particles changes", "because same temperature does not require the same number of particles"], "Keep average and crowd-size ideas separate.", ["same_temperature_same_internal_energy_confusion"], acceptance_rules=acceptance_groups(["average", "same pulse", "same temperature"], ["motion", "jiggle"], ["not crowd size", "different crowd size", "number of particles"]), skill_tags=["same_temp_average"]),
        ],
        "diagnostic": [
            mcq("M5L4_D1", "Which statement about temperature is strongest in this lesson?", ["Temperature tracks average particle motion", "Temperature is the total energy of the system", "Temperature is the same as mass", "Temperature tells how far apart all particles are"], 0, "Temperature is tied to average particle motion at this level.", ["temperature_internal_energy_confusion"], skill_tags=["temperature_average"]),
            mcq("M5L4_D2", "A small plaza and a large plaza have the same Pulse Level. Which claim is safest?", ["They must contain the same total energy", "They have the same average particle motion", "The larger plaza is automatically hotter", "The smaller plaza has stronger Grip Links"], 1, "Same pulse means same average, not same total.", ["same_temperature_same_internal_energy_confusion"], skill_tags=["same_temp_average"]),
            mcq("M5L4_D3", "Which description best fits a temperature reading?", ["A whole-system total", "An average motion reading", "A force reading", "A density reading"], 1, "The key word is average.", ["temperature_internal_energy_confusion"], skill_tags=["temperature_average"]),
            short("M5L4_D4", "Why is 'same temperature means same internal energy' weak?", ["because temperature is an average while internal energy is a total", "because same pulse level does not guarantee the same whole-system energy", "because systems can share the same average motion and still differ in total energy"], "Use average-versus-total language.", ["same_temperature_same_internal_energy_confusion"], acceptance_rules=acceptance_groups(["average", "same temperature", "pulse"], ["total", "whole system", "internal energy", "plaza store"], ["not same", "can differ", "does not guarantee"]), skill_tags=["temp_vs_store"]),
            mcq("M5L4_D5", "Which question does Pulse Level answer?", ["How energetic is one typical particle on average?", "How much energy is stored in all link arrangements in the system?", "How many particles are present?", "Which state is always most energetic?"], 0, "It is an average-particle question.", ["temperature_internal_energy_confusion"], skill_tags=["temperature_question"]),
            mcq("M5L4_D6", "Two samples are equally hot, but one contains twice as many particles. Which statement is strongest?", ["The larger sample can still have more total energy", "They must have the same total energy", "The larger sample is hotter", "The larger sample must be a gas"], 0, "Equal temperature does not force equal internal energy.", ["same_temperature_same_internal_energy_confusion"], skill_tags=["temp_vs_store"]),
            mcq("M5L4_D7", "What should stay fixed when you compare same-Pulse plazas?", ["Average jiggle", "Crowd size", "Total store", "State always"], 0, "Same pulse fixes the average motion reading.", ["temperature_internal_energy_confusion"], skill_tags=["same_temp_average"]),
            short("M5L4_D8", "How would you explain Pulse Level to a new learner?", ["it is how lively the average puck is", "it tells the average particle motion", "it is an average jiggle reading rather than the whole total energy"], "Use one-typical-puck or average-motion language.", ["temperature_internal_energy_confusion"], acceptance_rules=acceptance_groups(["average", "typical"], ["particle", "puck"], ["motion", "jiggle", "lively"]), skill_tags=["temperature_average"]),
        ],
        "transfer": [
            mcq("M5L4_M1", "A small hot sample and a large hot sample have the same temperature. What must match?", ["The average particle motion", "The total internal energy", "The number of particles", "The state"], 0, "Same temperature means same average motion at this level.", ["same_temperature_same_internal_energy_confusion"], skill_tags=["same_temp_average"]),
            mcq("M5L4_M2", "Which answer best keeps temperature and internal energy separate?", ["Temperature is average motion; internal energy is total kinetic-plus-potential energy", "Temperature and internal energy are always the same thing", "Temperature is mass per particle", "Internal energy means only link energy"], 0, "Keep average and total distinct.", ["temperature_internal_energy_confusion"], skill_tags=["temp_vs_store"]),
            short("M5L4_M3", "Why can two equally hot plazas still differ in total energy?", ["because they can have different numbers of particles", "because the same average motion does not fix the whole-system total", "because equal pulse does not guarantee equal plaza store"], "Use same-temperature and different-total language together.", ["same_temperature_same_internal_energy_confusion"], acceptance_rules=acceptance_groups(["same temperature", "same pulse", "equally hot"], ["different", "not equal"], ["number of particles", "whole system", "total", "plaza store", "internal energy"]), skill_tags=["temp_vs_store"]),
            mcq("M5L4_M4", "Which reading is most like a thermometer in the model?", ["Pulse Level", "Crowd Size", "Grip Dial", "Link Stretch map"], 0, "Pulse Level is the temperature analogue.", ["temperature_internal_energy_confusion"], skill_tags=["temperature_question"]),
            mcq("M5L4_M5", "A class says the large sample must be hotter because it has more particles. What is the best correction?", ["More particles can raise total energy without changing the temperature", "More particles always raise temperature", "Temperature depends only on mass", "Hotter means larger particles"], 0, "Particle count and temperature answer different questions.", ["same_temperature_same_internal_energy_confusion"], skill_tags=["temp_vs_store"]),
            short("M5L4_M6", "What is the difference between 'How lively is a typical puck?' and 'How much energy is in the whole plaza?'", ["the first is temperature and the second is internal energy", "the first is an average question and the second is a total question", "pulse level answers the first but plaza store answers the second"], "Use average-versus-total language.", ["temperature_internal_energy_confusion"], acceptance_rules=acceptance_groups(["first", "typical", "average", "temperature", "pulse"], ["second", "whole plaza", "total", "internal energy", "store"]), skill_tags=["temperature_question"]),
            mcq("M5L4_M7", "If two systems have the same average particle motion but one contains many more particles, which statement is strongest?", ["The larger system can have a larger total energy", "The systems must be identical in every way", "The smaller system must be a gas", "The larger system must be colder"], 0, "Same average does not fix the total.", ["same_temperature_same_internal_energy_confusion"], skill_tags=["temp_vs_store"]),
            mcq("M5L4_M8", "Which statement is weak at this stage?", ["Temperature is an average particle-motion idea", "Same temperature guarantees the same total internal energy", "Temperature does not directly equal crowd size", "Temperature is not particle size"], 1, "The total can differ even when the average matches.", ["same_temperature_same_internal_energy_confusion"], skill_tags=["temp_vs_store"]),
        ],
        "contract": contract(
            concept_targets=[
                "Define temperature as an average particle-motion idea",
                "Separate same-temperature claims from same-internal-energy claims",
                "Use same-pulse comparisons to reason about average versus total",
            ],
            core_concepts=[
                "Temperature is tied to average particle motion at this level.",
                "Pulse Level is an average-particle reading rather than a whole-system total.",
                "The same temperature does not guarantee the same internal energy.",
                "Crowd size can change total energy without changing the average particle motion.",
            ],
            prerequisite_lessons=["M5_L1", "M5_L2", "M5_L3"],
            misconception_focus=["temperature_internal_energy_confusion", "same_temperature_same_internal_energy_confusion"],
            formulas=[
                relation("temperature question = average particle motion", "Temperature answers how lively a typical particle is rather than how much total energy the whole system contains.", ["qualitative rule"], "Use when students collapse temperature into internal energy.")
            ],
            representations=[
                representation("words", "States temperature as an average before internal-energy totals are discussed."),
                representation("table", "Compares same Pulse Level across different crowd sizes."),
                representation("model", "Uses matched-pulse plazas to keep average and total distinct."),
            ],
            analogy_map=pulse_plaza_map("two plazas share the same Pulse Level but differ in crowd size"),
            worked_examples=[
                worked("A small plaza and a large plaza share the same Pulse Level. Which one is hotter?", ["Translate Pulse Level into the temperature question first.", "Keep the number of particles separate from the average particle motion.", "Answer only the question that temperature is designed to answer."], "They are equally hot in the sense of the same temperature.", "The same Pulse Level means the same average particle motion, so neither plaza is hotter just because it contains more particles.", "This is the key protection against equating temperature with amount of matter."),
                worked("Why can the larger plaza still contain more total energy even when the Pulse Level matches?", ["Keep the same average motion fixed.", "Notice that the larger plaza contains more particles sharing that average behavior.", "Connect more particles to a larger whole-system total."], "The larger plaza can still contain more total energy because there are more particles in the system.", "Internal energy is a whole-system total, so a bigger crowd can hold more total motion-and-link energy even at the same Pulse Level.", "This keeps same-temperature and same-total-energy claims from being confused."),
                worked("A learner says a system with more particles must be hotter. How should you respond?", ["Separate temperature from total amount of matter first.", "Use Pulse Level to answer the temperature question.", "State that particle number can change the total energy without changing the average motion."], "More particles do not automatically mean a higher temperature.", "Temperature is an average particle-motion reading, so crowd size alone does not decide it.", "This keeps temperature from being turned into a hidden size-of-system measure."),
            ],
            visual_assets=[visual("m5-l4-pulse-level", "temperature", "Same Pulse, different crowd", "Compares plazas with equal Pulse Level but different crowd sizes so temperature stays an average idea.", "Equal Pulse Level means equal average jiggle, not equal total whole-plaza energy.")],
            animation_assets=[animation("m5-l4-pulse-level-shift", "temperature", "Same Pulse comparisons", "Shows two plazas with matched pulse but different crowd sizes so the average stays fixed while the whole-system scale changes.")],
            simulation_contract={
                "asset_id": "m5_l4_pulse_temperature_lab",
                "concept": "temperature",
                "baseline_case": "Start with two same-pulse plazas and different crowd sizes so the average-versus-total contrast appears immediately.",
                "focus_prompt": "What stays the same when Pulse Level is matched, and what whole-system quantity is still allowed to differ?",
                "controls": [
                    {"variable": "pulse_level", "label": "Pulse Dial", "why_it_matters": "Sets the average particle liveliness for both plazas."},
                    {"variable": "crowd_a", "label": "Crowd A size", "why_it_matters": "Changes the size of one system without changing the average motion."},
                    {"variable": "crowd_b", "label": "Crowd B size", "why_it_matters": "Lets students compare same pulse with different amounts of matter."},
                ],
                "readouts": [
                    {"label": "Pulse Level", "meaning": "Shows the shared average-motion reading."},
                    {"label": "Average jiggle match", "meaning": "Confirms that the comparison is about the same temperature."},
                    {"label": "Whole-plaza motion total", "meaning": "Hints that total energy can still differ when crowd size changes."},
                ],
                "comparison_tasks": ["Keep the pulse the same while changing crowd size.", "Compare a smaller and larger plaza at the same pulse and explain what does and does not match."],
                "watch_for": "Students should not claim that more particles automatically means higher temperature.",
                "takeaway": "Temperature is an average particle-motion reading, not a whole-system total-energy reading.",
            },
            reflection_prompts=["Why can equal temperature and equal internal energy come apart?", "Why is temperature best treated as an average question here?"],
            mastery_skills=[
                "Define temperature accurately at the particle level",
                "Separate average from total",
                "Reject same-temperature same-internal-energy shortcuts",
                "Use same-pulse comparisons carefully",
                "Explain crowd-size effects without distorting temperature",
            ],
            variation_plan={
                "diagnostic": "Rotate between average-versus-total statements, same-pulse comparisons, and crowd-size misconceptions so attempts do not feel cloned.",
                "concept_gate": "Retry with matched-pulse plazas, thermometer-style wording, and average-question prompts rather than repeating a single statement stem.",
                "mastery": "Prefer unseen same-temperature comparisons with different crowd sizes or different total-system contexts before repeating any earlier item.",
            },
            scaffold_support=scaffold(
                "Temperature is an average particle-motion idea. It answers how lively a typical particle is, not how much total energy the whole system contains.",
                "Ask first whether the question is about an average particle or the entire system. If it is about a typical particle's motion, you are answering a temperature question.",
                "What can stay the same in two systems even while their total energy differs?",
                "Do not use system size alone to decide temperature. More particles can raise total energy without changing the average motion.",
                "The Pulse-Plaza helps because the same Pulse Dial can drive both a small and a large crowd, making the average motion the same even while the number of particles changes.",
                "Why is the Pulse Dial a better analogy for temperature than the total crowd size?",
                extra_sections=[
                    extra_section("Average versus total", "Temperature asks an average question. Internal energy asks a total whole-system question. Confusing them is like confusing average speed with total distance."),
                    extra_section("Same pulse does not force same store", "Matching average jiggle across two plazas does not automatically match the total energy stored across every particle and link."),
                ],
            ),
            visual_clarity_checks=visual_checks("temperature"),
        ),
    }


def lesson_l5() -> Dict[str, Any]:
    return {
        "id": "M5_L5",
        "title": "Plaza Store and Internal Energy",
        "sim": {
            "lab_id": "m5_plaza_store_lab",
            "title": "Plaza Store ledger",
            "description": "Separate the whole-system Plaza Store from Pulse Level by comparing crowd size and link arrangement at matched temperature.",
            "instructions": [
                "Keep Pulse Level fixed while you compare two different crowd sizes.",
                "Then keep Pulse Level fixed while you compare two different state arrangements.",
                "Explain Plaza Store as total motion-and-link energy for the whole system.",
            ],
            "outcomes": [
                "temperature_internal_energy_confusion",
                "same_temperature_same_internal_energy_confusion",
            ],
            "fields": ["pulse_level", "crowd_size", "state_mode", "kinetic_share", "link_share", "plaza_store"],
            "depth": "number of equal-temperature comparisons explained as different whole-system totals because crowd size or link arrangement changes",
        },
        "analogy_text": (
            "Plaza Store is the whole-system total: all the Jiggle Motion of all the pucks plus the Link Stretch energy stored in how they are arranged. "
            "So two plazas can share the same Pulse Level but still differ in Plaza Store because they have different crowd sizes or different link arrangements."
        ),
        "commitment_prompt": "Before you answer, decide whether the question is about average jiggle or the whole motion-and-link budget.",
        "micro_prompts": [
            prompt_block("What two parts make up Plaza Store?", "Use motion-and-link energy language."),
            prompt_block("How can two equal-pulse plazas still differ in store?", "Use crowd size or link arrangement."),
            prompt_block("Why is internal energy broader than temperature?", "Temperature is average motion; internal energy is the whole-system total."),
        ],
        "inquiry": [
            prompt_block("Hold Pulse Level fixed and increase the crowd size. Why does Plaza Store still rise?", "There are more particles contributing to the total."),
            prompt_block("Now hold pulse fixed but compare Slide Mode and Drift Mode. Why can the store still differ?", "Link arrangement changes the potential-energy part."),
            prompt_block("Explain Plaza Store without saying only 'temperature'.", "Use total kinetic-plus-potential language."),
        ],
        "recon_prompts": [
            "Internal energy is the total kinetic and potential energy of all the particles in the system.",
            "Plaza Store includes both Jiggle Motion and Link Stretch contributions.",
            "The same temperature does not guarantee the same internal energy.",
        ],
        "capsule_prompt": "Treat Plaza Store as a whole-system total so the kinetic and potential parts stay visible together.",
        "capsule_checks": [
            mcq("M5L5_C1", "What does Plaza Store represent?", ["The total kinetic and potential energy of all the particles", "Only the average particle motion", "Only the number of particles", "Only the force on the container"], 0, "Plaza Store is the whole-system total.", ["temperature_internal_energy_confusion"], skill_tags=["internal_energy_total"]),
            mcq("M5L5_C2", "Which pair makes up internal energy in this lesson?", ["Kinetic energy and potential energy", "Mass and volume", "Force and area", "Current and voltage"], 0, "Both motion and link arrangement matter.", ["temperature_internal_energy_confusion"], skill_tags=["kinetic_potential_parts"]),
            short("M5L5_C3", "Why can two plazas at the same Pulse Level still have different Plaza Stores?", ["because they can have different numbers of particles or different link arrangements", "because equal temperature does not fix the total kinetic-plus-potential energy", "because crowd size and link stretch can both change the whole-system total"], "Use crowd-size or arrangement language with total-energy language.", ["same_temperature_same_internal_energy_confusion"], acceptance_rules=acceptance_groups(["same pulse", "same temperature", "equal pulse"], ["different", "not same"], ["particles", "crowd size", "arrangement", "links", "potential", "total", "store"]), skill_tags=["temp_vs_store"]),
            mcq("M5L5_C4", "If two systems have the same temperature but one has many more particles, which statement is strongest?", ["The larger system can have a larger internal energy", "They must have equal internal energy", "The larger system must be hotter", "The smaller system must be a liquid"], 0, "Total energy can rise with more particles.", ["same_temperature_same_internal_energy_confusion"], skill_tags=["crowd_size_store"]),
            mcq("M5L5_C5", "Which statement about internal energy is strongest?", ["It includes the kinetic and potential energies of all particles", "It is only temperature by another name", "It depends only on state, not amount", "It is the same as force"], 0, "Internal energy is broader than temperature.", ["temperature_internal_energy_confusion"], skill_tags=["internal_energy_total"]),
            short("M5L5_C6", "Why can changing state change Plaza Store even at the same Pulse Level?", ["because the link arrangement changes the potential-energy part", "because internal energy includes how particles are arranged as well as how they move", "because different states can have different link energy even when average motion matches"], "Use potential-energy or link-arrangement language.", ["same_temperature_same_internal_energy_confusion"], acceptance_rules=acceptance_groups(["link", "arrangement", "potential"], ["different state", "same pulse", "same temperature", "average motion"], ["store", "internal energy", "change"]), skill_tags=["state_store_difference"]),
        ],
        "diagnostic": [
            mcq("M5L5_D1", "Internal energy is best described as...", ["the total kinetic and potential energy of all the particles", "the average kinetic energy of one particle only", "the same as temperature", "the pressure of the system"], 0, "Use whole-system total language.", ["temperature_internal_energy_confusion"], skill_tags=["internal_energy_total"]),
            mcq("M5L5_D2", "Which statement correctly defines internal energy in this lesson?", ["It is a whole-system total including kinetic and potential energy", "It must be equal whenever temperature is equal", "It is only temperature by another name", "It ignores arrangement and particle number"], 0, "Internal energy is broader than temperature.", ["same_temperature_same_internal_energy_confusion"], skill_tags=["temp_vs_store"]),
            mcq("M5L5_D3", "A larger crowd with the same Pulse Level can have more Plaza Store mainly because...", ["more particles contribute to the total", "the temperature must be higher", "the particles are bigger", "the average motion must be lower"], 0, "Total energy can rise with the number of particles.", ["same_temperature_same_internal_energy_confusion"], skill_tags=["crowd_size_store"]),
            short("M5L5_D4", "What two energy parts are included in internal energy?", ["kinetic and potential", "particle motion and link arrangement energy", "jiggle motion and link stretch"], "Name both the kinetic and potential parts.", ["temperature_internal_energy_confusion"], acceptance_rules=acceptance_groups(["kinetic", "motion", "jiggle"], ["potential", "link", "arrangement", "stretch"]), skill_tags=["kinetic_potential_parts"]),
            mcq("M5L5_D5", "Why can a gas and a liquid at the same Pulse Level still differ in Plaza Store?", ["Their link arrangements can store different potential energy", "They must have the same Plaza Store", "Temperature equals internal energy", "The gas has no particles"], 0, "State can change the potential-energy part.", ["same_temperature_same_internal_energy_confusion"], skill_tags=["state_store_difference"]),
            mcq("M5L5_D6", "Which question is an internal-energy question?", ["How much total motion-and-link energy is in the whole plaza?", "How lively is one typical particle?", "How many particles are visible?", "How big is one particle?"], 0, "Internal energy asks a total whole-system question.", ["temperature_internal_energy_confusion"], skill_tags=["internal_energy_question"]),
            mcq("M5L5_D7", "At the same Pulse Level, which change most directly increases Plaza Store?", ["adding more particles to the crowd", "renaming the state", "making one particle larger", "removing all motion"], 0, "More particles can raise the total.", ["same_temperature_same_internal_energy_confusion"], skill_tags=["crowd_size_store"]),
            short("M5L5_D8", "Why is internal energy broader than temperature?", ["because internal energy includes total kinetic and potential energy while temperature tracks average motion", "because internal energy is a total whole-system quantity but temperature is an average", "because temperature is only one part of the internal-energy story"], "Use average-versus-total plus kinetic/potential language.", ["temperature_internal_energy_confusion"], acceptance_rules=acceptance_groups(["internal energy", "store"], ["total", "whole system"], ["temperature", "average", "motion"], ["kinetic", "potential", "includes"]), skill_tags=["temp_vs_store"]),
        ],
        "transfer": [
            mcq("M5L5_M1", "Two samples have the same temperature. Sample A has twice as many particles as sample B. Which statement is strongest?", ["Sample A can have a larger internal energy", "Sample A must be hotter", "The internal energies must match", "Sample B must be a gas"], 0, "More particles can raise the total internal energy.", ["same_temperature_same_internal_energy_confusion"], skill_tags=["crowd_size_store"]),
            mcq("M5L5_M2", "Which answer best defines internal energy?", ["The total kinetic and potential energies of all the particles", "The average speed of the particles", "The amount of matter only", "The force between particles only"], 0, "Both kinetic and potential parts belong in the definition.", ["temperature_internal_energy_confusion"], skill_tags=["internal_energy_total"]),
            short("M5L5_M3", "Why can a liquid and gas at the same temperature still have different internal energies?", ["because their particle arrangements give different potential-energy contributions", "because state changes the link part of the store", "because equal average motion does not fix the potential-energy part"], "Use arrangement or potential-energy language.", ["same_temperature_same_internal_energy_confusion"], acceptance_rules=acceptance_groups(["same temperature", "same pulse", "equal average motion"], ["arrangement", "link", "potential"], ["different", "internal energy", "store", "state"]), skill_tags=["state_store_difference"]),
            mcq("M5L5_M4", "Which statement keeps temperature and internal energy most clearly separate?", ["Temperature is average motion; internal energy is whole-system kinetic-plus-potential total", "Temperature is just another name for internal energy", "Internal energy depends only on temperature", "Temperature counts particles"], 0, "That answer keeps the two questions distinct.", ["temperature_internal_energy_confusion"], skill_tags=["temp_vs_store"]),
            mcq("M5L5_M5", "A system gains particles without changing Pulse Level. Which quantity must rise most directly?", ["Plaza Store", "Particle size", "Temperature", "Pressure"], 0, "The whole-system total grows with more contributing particles.", ["same_temperature_same_internal_energy_confusion"], skill_tags=["crowd_size_store"]),
            short("M5L5_M6", "What is Link Stretch doing in the model?", ["it stands for the potential-energy part of internal energy", "it represents energy stored in particle arrangement", "it keeps the link contribution visible in the whole-system store"], "Use potential-energy or arrangement language.", ["temperature_internal_energy_confusion"], acceptance_rules=acceptance_groups(["link", "stretch", "arrangement"], ["potential", "stored", "internal energy", "store"]), skill_tags=["kinetic_potential_parts"]),
            mcq("M5L5_M7", "Which question should a Plaza Store meter answer?", ["How much total energy is in the whole particle system?", "How lively is one typical particle?", "Which state is warmer?", "How large is one particle?"], 0, "The meter is for the whole-system total.", ["temperature_internal_energy_confusion"], skill_tags=["internal_energy_question"]),
            mcq("M5L5_M8", "Which statement is weak?", ["Internal energy includes both kinetic and potential parts", "Same temperature guarantees same internal energy", "More particles can raise total energy at the same temperature", "State can affect internal energy through arrangement"], 1, "That is the misconception this lesson is designed to block.", ["same_temperature_same_internal_energy_confusion"], skill_tags=["temp_vs_store"]),
        ],
        "contract": contract(
            concept_targets=[
                "Define internal energy as a total kinetic-plus-potential store",
                "Explain why same temperature does not guarantee same internal energy",
                "Use crowd size and arrangement to compare internal-energy totals",
            ],
            core_concepts=[
                "Internal energy is the total kinetic and potential energy of all the particles in the system.",
                "Plaza Store includes both Jiggle Motion and Link Stretch contributions.",
                "The same temperature does not guarantee the same internal energy.",
                "State arrangement and crowd size can both change internal energy without changing temperature.",
            ],
            prerequisite_lessons=["M5_L1", "M5_L2", "M5_L3", "M5_L4"],
            misconception_focus=["temperature_internal_energy_confusion", "same_temperature_same_internal_energy_confusion"],
            formulas=[relation("internal energy = total kinetic + total potential of all particles", "Internal energy is a whole-system total with both motion and arrangement parts.", ["qualitative rule"], "Use when separating internal energy from temperature.")],
            representations=[
                representation("words", "Defines Plaza Store before quantitative comparisons are made."),
                representation("table", "Compares same-temperature systems with different crowd sizes or states."),
                representation("model", "Uses motion-and-link meters to keep kinetic and potential parts visible."),
            ],
            analogy_map=pulse_plaza_map("two same-pulse plazas differ in crowd size or link arrangement"),
            worked_examples=[
                worked("Two plazas have the same Pulse Level, but Plaza A has twice as many micro-pucks. Which one can have the larger Plaza Store?", ["Keep the average particle motion matched first.", "Then compare the total number of particles contributing to the whole-system store.", "Choose the system with the larger total contributing crowd."], "Plaza A can have the larger Plaza Store.", "With the same average motion, more particles can still produce a larger total kinetic-plus-potential energy.", "This blocks the shortcut that same temperature forces the same internal energy."),
                worked("Why can a Slide-Mode plaza and a Drift-Mode plaza at the same Pulse Level still differ in Plaza Store?", ["Hold the average motion match fixed.", "Now compare the link arrangement in the two states.", "Use the change in potential-energy contribution to explain the store difference."], "They can differ because the arrangement and link energy are different.", "Internal energy includes potential energy from arrangement as well as kinetic energy from motion.", "This keeps internal energy broader than temperature."),
                worked("A learner says internal energy means only how fast the particles are moving. How should you correct that?", ["Keep the kinetic part, because it is real.", "Add the stored energy in how the particles are arranged and linked.", "Restate the full definition as a whole-system total."], "Internal energy includes both particle motion energy and arrangement energy.", "The full store counts both kinetic and potential contributions across the whole system.", "This prevents temperature language from swallowing the whole internal-energy idea."),
            ],
            visual_assets=[visual("m5-l5-plaza-store", "internal_energy", "Plaza Store board", "Separates Pulse Level from the whole kinetic-plus-potential store.", "Equal pulse does not guarantee equal Plaza Store because crowd size and link arrangement can still change the total.")],
            animation_assets=[animation("m5-l5-plaza-store-shift", "internal_energy", "Same Pulse, different Store", "Shows same-pulse plazas with changing crowd size and link arrangement so the total store changes without changing the average jiggle.")],
            simulation_contract={
                "asset_id": "m5_l5_plaza_store_lab",
                "concept": "internal_energy",
                "baseline_case": "Start with two same-pulse plazas and one crowd-size difference so the total-store contrast appears immediately.",
                "focus_prompt": "How can the same average particle motion still leave two systems with different total kinetic-plus-potential energy?",
                "controls": [
                    {"variable": "pulse_level", "label": "Pulse Dial", "why_it_matters": "Keeps the average-motion reading visible."},
                    {"variable": "crowd_size", "label": "Crowd Size", "why_it_matters": "Changes how many particles contribute to the total store."},
                    {"variable": "state_mode", "label": "State arrangement", "why_it_matters": "Changes the link-energy part without necessarily changing the pulse."},
                ],
                "readouts": [
                    {"label": "Pulse Level", "meaning": "Shows the average-motion reading related to temperature."},
                    {"label": "Kinetic share", "meaning": "Shows the motion contribution to the total store."},
                    {"label": "Link share", "meaning": "Shows the arrangement contribution to the total store."},
                    {"label": "Plaza Store", "meaning": "Shows the whole-system internal-energy total."},
                ],
                "comparison_tasks": ["Keep pulse fixed while changing crowd size.", "Keep pulse fixed while changing the state arrangement."],
                "watch_for": "Students should not claim that equal pulse automatically forces equal Plaza Store.",
                "takeaway": "Internal energy is a whole-system total of kinetic and potential parts, so equal temperature does not force equal internal energy.",
            },
            reflection_prompts=["Why is internal energy a broader idea than temperature?", "Why can two equal-temperature systems still differ in total energy?"],
            mastery_skills=[
                "Define internal energy correctly",
                "Separate internal energy from temperature",
                "Use crowd-size reasoning in internal-energy comparisons",
                "Use arrangement reasoning in internal-energy comparisons",
                "Keep kinetic and potential parts visible",
            ],
            variation_plan={
                "diagnostic": "Rotate among whole-system definition questions, same-temperature comparisons, and kinetic-versus-potential structure checks so attempts stay broad.",
                "concept_gate": "Retry through new same-pulse scenarios, larger-versus-smaller crowds, and different-state comparisons rather than the same stem.",
                "mastery": "Prefer unseen equal-temperature-but-unequal-store contexts and new crowd-size or arrangement changes before repeating any prior item.",
            },
            scaffold_support=scaffold(
                "Internal energy is the total kinetic and potential energy of all the particles in the system, so it is broader than temperature.",
                "Answer the average-motion question first only if the prompt is about temperature. If the prompt asks about the whole system, keep both the kinetic part and the arrangement part visible.",
                "What extra part of the store must you keep in view once the question stops being only about average motion?",
                "Do not use equal temperature as proof of equal internal energy. The total can change with crowd size and arrangement.",
                "Plaza Store makes the whole-system total visible, while Pulse Level keeps the average in view. The model is strongest when you keep both meters visible at once.",
                "Why is one meter not enough to tell the whole energy story of the plaza?",
                extra_sections=[
                    extra_section("Kinetic and potential together", "Internal energy needs both the motion of particles and the energy stored in how they are arranged and linked."),
                    extra_section("Same pulse, different store", "Equal average motion can still leave different whole-system totals because different numbers of particles or different link arrangements are contributing."),
                ],
            ),
            visual_clarity_checks=visual_checks("internal-energy"),
        ),
    }


def lesson_l6() -> Dict[str, Any]:
    return {
        "id": "M5_L6",
        "title": "State Change Energy Missions",
        "sim": {
            "lab_id": "m5_state_change_lab",
            "title": "State-change mission deck",
            "description": "Track where added energy goes during a state change so Plaza Store can rise even when Pulse Level changes only a little.",
            "instructions": [
                "Add energy to a plaza near melting or boiling conditions.",
                "Watch how some of the added energy loosens Grip Links instead of greatly raising Pulse Level.",
                "Explain the mission using kinetic and potential parts of the Plaza Store.",
            ],
            "outcomes": [
                "state_change_energy_confusion",
                "temperature_internal_energy_confusion",
            ],
            "fields": ["energy_input", "pulse_level", "link_release", "state_progress", "plaza_store"],
            "depth": "number of state-change missions explained by tracking where the added energy goes rather than assuming temperature must always rise sharply",
        },
        "analogy_text": (
            "During a state change, extra mission energy can go into loosening Grip Links instead of making the average jiggle rise sharply. "
            "That means Plaza Store can increase while Pulse Level changes only a little, because some added energy is shifting the arrangement part of the system."
        ),
        "commitment_prompt": "Before you answer, decide whether the added energy is mostly raising average jiggle, loosening links, or both.",
        "micro_prompts": [
            prompt_block("Why can Plaza Store rise during melting even if Pulse Level changes only a little?", "Use link-loosening or potential-energy language."),
            prompt_block("What part of internal energy changes strongly during a state change?", "Use the arrangement or link part."),
            prompt_block("Why is 'adding energy always means higher temperature' weak?", "State changes can use energy to loosen links."),
        ],
        "inquiry": [
            prompt_block("Add energy while the plaza is already close to changing state. What happens to the Grip Links?", "Use loosening-link language."),
            prompt_block("Compare the rise in Pulse Level with the rise in Plaza Store. Why can they separate?", "Added energy can feed potential energy as well as kinetic energy."),
            prompt_block("Explain a melting or boiling mission without saying only 'it gets hotter'.", "Track kinetic and potential parts explicitly."),
        ],
        "recon_prompts": [
            "Adding energy does not always mean a large temperature rise.",
            "During a state change, added energy can go into loosening particle attractions.",
            "Plaza Store can rise even when Pulse Level changes only a little.",
        ],
        "capsule_prompt": "Use the split between average jiggle and link loosening so state change energy stays richer than a one-meter story.",
        "capsule_checks": [
            mcq("M5L6_C1", "Why can Pulse Level stay almost unchanged while Plaza Store rises during melting?", ["Added energy is going into loosening Grip Links", "Particles stop moving", "The particles become larger", "Internal energy falls"], 0, "State change can feed the arrangement part strongly.", ["state_change_energy_confusion"], skill_tags=["state_change_links"]),
            mcq("M5L6_C2", "Which statement is strongest during a state change?", ["Added energy must always sharply raise temperature", "Added energy can increase internal energy without a large rise in Pulse Level", "Temperature and internal energy are identical", "Particles vanish"], 1, "State change energy can feed link changes.", ["state_change_energy_confusion"], skill_tags=["temp_vs_internal_during_change"]),
            short("M5L6_C3", "Why is 'adding energy always means higher temperature' weak?", ["because some added energy can loosen links instead of greatly raising average motion", "because internal energy can rise through the potential-energy part during a state change", "because state change energy can go into arrangement rather than only temperature"], "Use link-loosening or potential-energy language.", ["state_change_energy_confusion"], acceptance_rules=acceptance_groups(["added energy", "state change"], ["link", "arrangement", "potential", "loosen"], ["temperature", "pulse", "not always", "instead"]), skill_tags=["state_change_links"]),
            mcq("M5L6_C4", "Which part of the store is especially important during melting?", ["The arrangement or potential-energy part", "Only the force on the container", "Particle size", "Only mass"], 0, "Melting needs energy to change particle arrangement.", ["state_change_energy_confusion"], skill_tags=["potential_in_change"]),
            mcq("M5L6_C5", "A system gains energy during boiling. Which statement can still be true?", ["The internal energy rises even if temperature changes little", "The internal energy must stay fixed", "The particles become bigger", "The pressure must be zero"], 0, "Internal energy can rise through arrangement changes.", ["state_change_energy_confusion"], skill_tags=["temp_vs_internal_during_change"]),
            short("M5L6_C6", "Why can Plaza Store rise while Pulse Level barely rises?", ["because total energy can increase through the link or potential part", "because added energy can loosen attractions instead of mainly increasing average motion", "because the whole-system store includes more than the pulse reading"], "Use total-store and link language together.", ["state_change_energy_confusion"], acceptance_rules=acceptance_groups(["store", "internal energy", "total"], ["link", "potential", "arrangement", "attractions"], ["pulse", "temperature", "average motion", "barely"]), skill_tags=["temp_vs_internal_during_change"]),
        ],
        "diagnostic": [
            mcq("M5L6_D1", "Which statement best keeps state-change energy reasoning accurate?", ["Added energy can loosen particle links during a state change", "Added energy must always raise temperature sharply", "Particles must get bigger when energy is added", "Internal energy cannot rise during melting or boiling"], 0, "State-change energy can feed arrangement changes, not just temperature rise.", ["state_change_energy_confusion"], skill_tags=["state_change_links"]),
            mcq("M5L6_D2", "During melting, added energy is often used mainly to...", ["loosen attractions between particles", "increase particle size", "remove all particles", "stop motion completely"], 0, "State change needs energy for arrangement changes.", ["state_change_energy_confusion"], skill_tags=["potential_in_change"]),
            mcq("M5L6_D3", "Which quantity can rise even if temperature changes only a little?", ["Internal energy", "Particle size", "Mass", "Pressure alone"], 0, "Internal energy is broader than temperature.", ["temperature_internal_energy_confusion"], skill_tags=["temp_vs_internal_during_change"]),
            short("M5L6_D4", "Why can a state change absorb energy without a big temperature rise?", ["because the energy can go into changing particle arrangement", "because the added energy can loosen links instead of mainly speeding particles up", "because potential energy can rise during the change"], "Use arrangement or link language.", ["state_change_energy_confusion"], acceptance_rules=acceptance_groups(["energy", "state change"], ["arrangement", "link", "potential", "loosen"], ["temperature", "pulse", "not big", "little"]), skill_tags=["state_change_links"]),
            mcq("M5L6_D5", "Which statement best compares temperature and internal energy during a state change?", ["Temperature tracks average motion, but internal energy can rise through kinetic and potential changes", "They always stay equal", "Internal energy stops changing", "Temperature measures the number of particles"], 0, "Keep the average-versus-total split visible.", ["temperature_internal_energy_confusion"], skill_tags=["temp_vs_internal_during_change"]),
            mcq("M5L6_D6", "A plateau-like heating stage is most consistent with...", ["energy going into loosening particle attractions", "particles becoming larger", "all collisions stopping", "gravity vanishing"], 0, "This is the state-change energy story.", ["state_change_energy_confusion"], skill_tags=["potential_in_change"]),
            mcq("M5L6_D7", "Which part of internal energy is highlighted most when Grip Links are loosened?", ["Potential-energy part", "Mass part", "Pressure part", "Charge part"], 0, "Grip-link changes belong to the arrangement or potential contribution.", ["state_change_energy_confusion"], skill_tags=["potential_in_change"]),
            short("M5L6_D8", "How would you explain melting in the Pulse-Plaza model?", ["added energy loosens grip links so the locked crowd can slide", "the system uses energy to change arrangement from lock mode to slide mode", "plaza store rises while links loosen and the state changes"], "Use link-loosening and state-change language.", ["state_change_energy_confusion"], acceptance_rules=acceptance_groups(["energy", "store", "added"], ["loosen", "links", "arrangement", "grip"], ["state", "melt", "lock", "slide"]), skill_tags=["state_change_links"]),
        ],
        "transfer": [
            mcq("M5L6_M1", "A solid is heated and begins to melt. Which statement is strongest?", ["Some added energy is being used to loosen attractions rather than only raising temperature", "All added energy must sharply raise temperature", "The particles grow larger", "Internal energy cannot change"], 0, "Melting uses energy to change arrangement.", ["state_change_energy_confusion"], skill_tags=["state_change_links"]),
            mcq("M5L6_M2", "Which answer best explains why internal energy rises during a state change?", ["Because total kinetic-plus-potential energy can rise even when average motion changes little", "Because particle size increases", "Because pressure becomes temperature", "Because attractions vanish without energy"], 0, "Internal energy includes the link part too.", ["temperature_internal_energy_confusion"], skill_tags=["temp_vs_internal_during_change"]),
            short("M5L6_M3", "Why can boiling need energy even if the temperature reading changes little?", ["because energy is needed to loosen and separate particle links", "because the arrangement part of internal energy is increasing", "because added energy can feed the potential part during the change"], "Use separation, links, or potential-energy language.", ["state_change_energy_confusion"], acceptance_rules=acceptance_groups(["energy", "boiling", "state change"], ["loosen", "separate", "links", "arrangement", "potential"], ["temperature", "little", "same", "barely"]), skill_tags=["state_change_links"]),
            mcq("M5L6_M4", "Which statement is weak?", ["Internal energy can rise without a large temperature rise during a state change", "Added energy can loosen links", "Temperature always rises sharply whenever energy is added", "Potential energy can change during melting"], 2, "That is the over-simple rule being rejected.", ["state_change_energy_confusion"], skill_tags=["temp_vs_internal_during_change"]),
            mcq("M5L6_M5", "What does the model use Grip Links for during a state change?", ["To make the potential-energy part visible", "To measure mass", "To replace temperature", "To show particle size"], 0, "Grip Links keep the arrangement energy visible.", ["state_change_energy_confusion"], skill_tags=["potential_in_change"]),
            short("M5L6_M6", "What is the best way to explain a small temperature rise with a large energy input during melting?", ["much of the energy is going into changing the arrangement rather than only increasing average motion", "the added energy is feeding link loosening and the potential part", "internal energy is rising through the state change even though pulse rises only a little"], "Use arrangement and average-motion language together.", ["state_change_energy_confusion"], acceptance_rules=acceptance_groups(["energy", "melting", "state change"], ["arrangement", "link", "potential", "loosen"], ["average motion", "pulse", "temperature", "little"]), skill_tags=["temp_vs_internal_during_change"]),
            mcq("M5L6_M7", "Which mission statement is strongest?", ["A state change is a split-store problem: some added energy changes links rather than only jiggle", "A state change is just a pressure change", "A state change means particles get larger", "A state change proves no energy is stored"], 0, "The best answer keeps kinetic and potential roles visible.", ["state_change_energy_confusion"], skill_tags=["state_change_links"]),
            mcq("M5L6_M8", "What should you track first in a state-change energy mission?", ["Where the added energy is going within the store", "Only the final temperature", "Only the particle size", "Only the number of particles"], 0, "The destination of the energy matters before the final reading.", ["state_change_energy_confusion"], skill_tags=["energy_destination"]),
        ],
        "contract": contract(
            concept_targets=[
                "Explain why adding energy does not always sharply raise temperature",
                "Track state-change energy through link loosening and total store increase",
                "Use internal energy to explain melting and boiling more deeply",
            ],
            core_concepts=[
                "Adding energy does not always mean a large temperature rise.",
                "During a state change, added energy can go into loosening particle attractions.",
                "Internal energy can rise even when temperature changes only a little.",
                "State changes are total-energy and arrangement changes, not particle-size changes.",
            ],
            prerequisite_lessons=["M5_L1", "M5_L2", "M5_L3", "M5_L4", "M5_L5"],
            misconception_focus=["state_change_energy_confusion", "temperature_internal_energy_confusion"],
            formulas=[relation("state change: added energy can raise internal energy through arrangement changes", "State-change energy can feed the potential-energy part instead of strongly increasing average motion straight away.", ["qualitative rule"], "Use when explaining melting or boiling.")],
            representations=[
                representation("words", "States the state-change energy rule directly before symbolic shortcuts appear."),
                representation("model", "Shows added energy splitting between average jiggle and link loosening."),
                representation("diagram", "Keeps the state progression and energy destination visible together."),
            ],
            analogy_map=pulse_plaza_map("added energy loosens links during a state change"),
            worked_examples=[
                worked("A learner says melting must mean particles get bigger because energy is added. How should the model correct this?", ["Keep the size rule from Lesson 1 fixed first.", "Redirect the added energy into loosened Grip Links and changing arrangement.", "State the new mode change without changing particle size."], "Melting changes arrangement and link energy, not particle size.", "The added energy helps the locked crowd loosen into a sliding one; the particles themselves do not grow.", "This brings the module back to its first protection rule while extending it through state-change energy."),
                worked("Why can Plaza Store rise during melting while Pulse Level changes only a little?", ["Keep the average-motion reading visible but not exclusive.", "Add the link-loosening contribution to the total store story.", "Explain that internal energy rises because the arrangement part is changing."], "The total store rises because energy is going into loosening links as well as any motion change.", "Internal energy includes the potential-energy part, so state change can increase the store even without a large temperature jump.", "This is the capstone distinction between temperature and internal energy."),
                worked("A state-change mission adds energy to a liquid just before boiling. What should you track first?", ["Ask where the added energy is going inside the system.", "Check whether the energy mainly raises average jiggle or helps separate particles further.", "Use that destination to explain the next stage of the mission."], "Track the energy destination first: motion change, link loosening, or both.", "State-change reasoning is strongest when the learner decides what the added energy is doing before focusing on the final reading.", "This turns state change into deliberate energy accounting rather than rote phrase recall."),
            ],
            visual_assets=[visual("m5-l6-state-change", "state_change", "State-change mission deck", "Shows added energy splitting between pulse rise and link loosening as the plaza changes state.", "Plaza Store can rise while Pulse Level changes only a little because some added energy is changing arrangement rather than mainly average motion.")],
            animation_assets=[animation("m5-l6-state-change-shift", "state_change", "Loosening links during state change", "Shows added energy being routed into link loosening so the state changes while the pulse meter rises only slightly.")],
            simulation_contract={
                "asset_id": "m5_l6_state_change_lab",
                "concept": "state_change",
                "baseline_case": "Start with a plaza close to a state boundary so added energy can visibly split between pulse rise and link loosening.",
                "focus_prompt": "When extra energy enters the system, does it mainly raise average motion, loosen links, or do both?",
                "controls": [
                    {"variable": "energy_input", "label": "Added mission energy", "why_it_matters": "Controls how much new energy enters the system."},
                    {"variable": "pulse_level", "label": "Pulse Dial", "why_it_matters": "Keeps the average-motion part visible."},
                    {"variable": "link_release", "label": "Grip-link loosening", "why_it_matters": "Keeps the arrangement part visible during the state change."},
                ],
                "readouts": [
                    {"label": "Pulse Level", "meaning": "Shows how much the average particle motion is changing."},
                    {"label": "Link release", "meaning": "Shows how much added energy is going into arrangement change."},
                    {"label": "State progress", "meaning": "Shows how far the system has moved toward the next state."},
                    {"label": "Plaza Store", "meaning": "Shows the total internal-energy change across the mission."},
                ],
                "comparison_tasks": ["Compare a small-energy input with a large one near a state boundary.", "Compare a case where most energy raises pulse with one where most energy loosens links."],
                "watch_for": "Students should not claim that every energy input must mainly show up as a temperature rise.",
                "takeaway": "During a state change, added energy can raise internal energy by loosening links even when the pulse meter changes only a little.",
            },
            reflection_prompts=["Why can added energy fail to produce a large temperature rise during a state change?", "Why is it useful to track where the energy goes during melting or boiling?"],
            mastery_skills=[
                "Explain state-change energy conceptually",
                "Separate temperature rise from internal-energy rise",
                "Use link-loosening language accurately",
                "Track energy destination in a multi-step story",
                "Connect state change to the particle model",
            ],
            variation_plan={
                "diagnostic": "Rotate among melting, boiling, and generic added-energy claims so students meet the core idea in several state-change contexts.",
                "concept_gate": "Retry with different energy-destination stories and different particle-language prompts rather than repeating one stem.",
                "mastery": "Prefer unseen state-change missions that vary the energy destination, the state involved, and the wording of the misconception before repeating earlier items.",
            },
            scaffold_support=scaffold(
                "A state change is not just a temperature-rise story. Added energy can go into loosening links and changing arrangement, so internal energy rises even when pulse rises only a little.",
                "Track the energy destination first. Ask whether the added energy mainly increases average motion, loosens links, or does both, then explain the state response from that split.",
                "Why is it not enough to watch only the pulse meter during a state change?",
                "Do not assume added energy must always show up mainly as a temperature rise. During a state change, the arrangement part can take a large share.",
                "The Pulse-Plaza makes state change visible as a tug between rising average jiggle and loosening Grip Links, so the learner can see why store change and temperature change do not always track one another closely.",
                "Which meter tells you more during melting: the Pulse Level alone or the Pulse Level together with Link Release?",
                extra_sections=[
                    extra_section("Where the energy goes", "State-change questions are strongest when the learner first decides whether the added energy is feeding kinetic change, potential change, or both."),
                    extra_section("No bigger particles", "Even in the capstone state-change lesson, the micro-pucks never get bigger. The changing story is in motion and arrangement, not particle size."),
                ],
            ),
            visual_clarity_checks=visual_checks("state-change"),
        ),
    }


M5_SPEC = {
    "authoring_standard": AUTHORING_STANDARD_V3,
    "module_description": (
        "Particle model and internal energy: states of matter, Brownian motion, temperature, internal energy, "
        "and state-change reasoning are kept inside one particle world."
    ),
    "mastery_outcomes": [
        "Describe solids, liquids, and gases using particle spacing, motion, and attraction.",
        "Explain why particles do not get bigger when heated and why bulk properties do not belong to one particle.",
        "Explain Brownian motion as evidence of constant random collisions from surrounding particles.",
        "Describe temperature as an average particle-motion idea.",
        "Describe internal energy as the total kinetic and potential energy of all the particles in a system.",
        "Explain why equal temperature does not necessarily mean equal internal energy.",
        "Explain why added energy during a state change can increase internal energy without a large temperature rise.",
    ],
    "lessons": [lesson_l1(), lesson_l2(), lesson_l3(), lesson_l4(), lesson_l5(), lesson_l6()],
}


RELEASE_CHECKS = [
    "Every lesson keeps particle size fixed while motion, spacing, attraction, or arrangement change.",
    "Every lesson uses the Pulse-Plaza analogy to deepen the formal particle model rather than to replace it.",
    "Every worked example states why the answer follows, not just the classification or arithmetic.",
    "Temperature and internal energy remain clearly separated through average-versus-total reasoning across the module.",
]


M5_MODULE_DOC, M5_LESSONS, M5_SIM_LABS = build_nextgen_module_bundle(
    module_id=M5_MODULE_ID,
    module_title=M5_MODULE_TITLE,
    module_spec=M5_SPEC,
    allowlist=M5_ALLOWLIST,
    content_version=M5_CONTENT_VERSION,
    release_checks=RELEASE_CHECKS,
    sequence=9,
    level="Module 5",
    estimated_minutes=285,
    authoring_standard=AUTHORING_STANDARD_V3,
    plan_assets=True,
    public_base="/lesson_assets",
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed Module M5 into Firestore")
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

    module_doc = deepcopy(M5_MODULE_DOC)
    lesson_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in M5_LESSONS]
    sim_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in M5_SIM_LABS]

    if args.compile_assets:
        render_module_assets(lesson_pairs, sim_pairs, asset_root=asset_root, public_base=args.public_base)

    print_preview(module_doc, lesson_pairs, sim_pairs)
    db = init_firebase(project)
    plan: List[Tuple[str, str]] = [("modules", M5_MODULE_ID)]
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
