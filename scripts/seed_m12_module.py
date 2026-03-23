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


M12_MODULE_ID = "M12"
M12_CONTENT_VERSION = "20260321_m12_field_weave_v3"
M12_MODULE_TITLE = "Magnetism & Electromagnetic Effects"
M12_ALLOWLIST = [
    "current_magnetism_separate_confusion",
    "field_lines_as_paths_confusion",
    "compass_points_to_force_confusion",
    "wire_field_direction_confusion",
    "electromagnet_strength_confusion",
    "soft_iron_core_confusion",
    "magnetic_force_forward_confusion",
    "force_direction_reversal_confusion",
    "motor_effect_vs_induction_confusion",
    "commutator_role_confusion",
    "induction_static_field_confusion",
    "lenz_law_confusion",
    "generator_current_type_confusion",
    "transformer_dc_confusion",
    "turns_ratio_confusion",
    "transmission_voltage_loss_confusion",
]


def safe_tags(tags: Sequence[str]) -> List[str]:
    allowed = set(M12_ALLOWLIST)
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


VALID_REPRESENTATION_KINDS = {"diagram", "equation_story", "formula", "graph", "model", "table", "words"}


def canonical_representation_kind(kind: str) -> str:
    normalized = str(kind).strip().lower()
    if normalized in VALID_REPRESENTATION_KINDS:
        return normalized
    if "table" in normalized:
        return "table"
    if "equation" in normalized or "formula" in normalized:
        return "formula"
    if "model" in normalized:
        return "model"
    if any(token in normalized for token in ["diagram", "sketch", "map", "flow", "cycle", "comparison", "pole"]):
        return "diagram"
    return "words"


def normalize_representations(
    representations: Sequence[Dict[str, Any]],
    formulas: Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    normalized_items: List[Dict[str, Any]] = []
    for item in representations:
        normalized_item = deepcopy(item)
        original_kind = str(normalized_item.get("kind") or "words")
        normalized_item["kind"] = canonical_representation_kind(original_kind)
        if normalized_item["kind"] != original_kind:
            normalized_item.setdefault("label", original_kind)
        normalized_items.append(normalized_item)

    kinds = {str(item.get("kind") or "") for item in normalized_items}
    if "words" not in kinds:
        normalized_items.append(representation("words", "States the idea in clear lesson language before any diagram or calculation."))
    if formulas and "formula" not in kinds:
        normalized_items.append(representation("formula", "Connects the lesson's key relationship to the field-weave reasoning."))
    if not any(kind in {"diagram", "graph", "table", "model"} for kind in kinds):
        normalized_items.append(representation("diagram", "Adds a spatial or comparison view so the lesson is not text-only."))

    return normalized_items


def worked(prompt: str, steps: Sequence[str], final_answer: str, answer_reason: str, why_it_matters: str) -> Dict[str, Any]:
    return {
        "prompt": prompt,
        "steps": list(steps),
        "final_answer": final_answer,
        "answer_reason": answer_reason,
        "why_it_matters": why_it_matters,
    }


def visual(asset_id: str, concept: str, title: str, purpose: str, caption: str) -> Dict[str, Any]:
    return {
        "asset_id": asset_id,
        "concept": concept,
        "phase_key": "analogical_grounding",
        "title": title,
        "purpose": purpose,
        "caption": caption,
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
        "fresh_attempt_policy": "Prefer unseen lesson-owned questions in diagnostic, concept-gate, and mastery before repeating any previous stem.",
    }


def visual_checks(topic: str) -> List[str]:
    return [
        f"The main {topic} labels stay fully visible on desktop and mobile.",
        "Field arrows, current directions, and force arrows stay visually distinct instead of collapsing into one bundle of lines.",
        "Compass markers, coil labels, and transformer readouts remain readable without clipping or overlapping the main geometry.",
        "Direction and strength cues are separated so the diagram does not confuse where the field points with how strong it is.",
    ]


def field_weave_map(focus: str) -> Dict[str, Any]:
    return {
        "model_name": "Field-Weave Model",
        "focus": focus,
        "comparison": f"The Field-Weave world extends the earlier carrier-loop family by showing how moving carriers create fields and how changing fields can create new pushes while {focus}.",
        "mapping": [
            "Field tower -> permanent magnet",
            "Weave lines -> magnetic field lines",
            "Compass flag -> test compass / north-seeking probe",
            "Weave density -> field strength",
            "Carrier route -> current-carrying wire",
            "Weave rings -> circular field around a wire",
            "Coil tower -> solenoid / electromagnet",
            "Core spine -> soft-iron core",
            "Side-kick -> magnetic force",
            "Spin frame -> motor coil",
            "Change-thread -> changing magnetic flux",
            "Loop push -> induced emf or induced current",
            "Turn-wheel -> generator",
            "Twin-coil bridge -> transformer",
        ],
        "limit": "The model keeps the field story coherent, but students still need standard language such as field direction, induced emf, alternating output, and turns ratio.",
        "prediction_prompt": f"Use the Field-Weave model to predict what should happen when {focus}.",
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
    normalized_representations = normalize_representations(representations, formulas)
    return {
        "concept_targets": list(concept_targets),
        "core_concepts": list(core_concepts),
        "prerequisite_lessons": list(prerequisite_lessons),
        "misconception_focus": safe_tags(misconception_focus),
        "formulas": [deepcopy(item) for item in formulas],
        "representations": [deepcopy(item) for item in normalized_representations],
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


def field_lines_lesson() -> Dict[str, Any]:
    d = [
        mcq("M12L1_D1", "A Field Tower in this module stands for a...", ["permanent magnet", "battery", "generator coil", "transformer core"], 0, "A field tower is the permanent-magnet source of field.", ["current_magnetism_separate_confusion"], skill_tags=["field_source"]),
        mcq("M12L1_D2", "Weave lines show the...", ["direction pattern of the magnetic field", "literal path of moving particles", "resistance of the wire", "voltage of the source"], 0, "Field lines are a direction-and-strength map, not particle tracks.", ["field_lines_as_paths_confusion"], skill_tags=["field_line_meaning"]),
        mcq("M12L1_D3", "A Compass Flag mainly tells you...", ["the local field direction", "the magnetic force size only", "the current in a wire", "the energy stored in a magnet"], 0, "A small compass aligns with the local magnetic field direction.", ["compass_points_to_force_confusion"], skill_tags=["compass_use"]),
        short("M12L1_D4", "Why do denser weave lines represent a stronger field?", ["Because closer field lines indicate a stronger magnetic field in that region.", "Because the tighter spacing is used to show a larger field strength."], "Use density-as-strength map language.", ["field_lines_as_paths_confusion"], skill_tags=["field_strength"], acceptance_rules=acceptance_groups(["closer", "denser", "tighter"], ["field lines", "weave lines"], ["stronger", "larger"], ["field", "field strength"])),
        mcq("M12L1_D5", "Around a straight current-carrying wire, the weave pattern is mainly...", ["circular", "radial like spokes", "parallel straight lines only", "random"], 0, "A straight wire produces circular magnetic field lines around itself.", ["wire_field_direction_confusion"], skill_tags=["wire_field_shape"]),
        mcq("M12L1_D6", "If the current in that wire reverses, the circular field direction...", ["reverses", "stays the same forever", "disappears completely", "becomes radial"], 0, "Reversing current reverses the wire-field direction.", ["wire_field_direction_confusion"], skill_tags=["wire_field_reversal"]),
        short("M12L1_D7", "Why is it weak to call field lines 'tracks that particles follow'?", ["Because field lines are a map of field direction and strength, not literal tracks for matter to travel along.", "Because the diagram shows the field pattern, rather than a physical railway for particles."], "Keep the diagram as a map, not a path.", ["field_lines_as_paths_confusion"], skill_tags=["field_line_meaning"], acceptance_rules=acceptance_groups(["field lines", "weave lines"], ["map", "diagram"], ["direction", "strength"], ["not", "rather than"], ["path", "track", "railway"])),
        mcq("M12L1_D8", "Outside a bar magnet, the field direction is usually drawn from...", ["north pole to south pole", "south pole to north pole", "center outward equally", "the compass to the wire"], 0, "Outside the magnet, field lines run from north to south.", ["field_lines_as_paths_confusion"], skill_tags=["magnet_field_direction"]),
        mcq("M12L1_D9", "Which statement best links electricity and magnetism already?", ["A current-carrying wire creates a magnetic field in space.", "A magnetic field can exist only inside a battery.", "Magnetism starts only when a motor spins.", "Compasses measure voltage directly."], 0, "Current already creates magnetic field, so the topics are connected.", ["current_magnetism_separate_confusion"], skill_tags=["electric_magnetic_link"]),
        mcq("M12L1_D10", "Best first question when reading a magnetic-field diagram:", ["What creates the field here, and what direction does the field have at this point?", "How much resistance is in the battery?", "Which wire is hottest?", "What is the power rating of the lamp?"], 0, "Name the field source and local field direction first.", ["field_lines_as_paths_confusion"], skill_tags=["prediction_habit"]),
    ]
    c = [
        short("M12L1_C1", "What job does a Compass Flag do in the Field-Weave model?", ["It lines up with the local magnetic field and shows the field direction at that point.", "It acts as a small test compass that reveals which way the field points locally."], "A compass flag is a direction probe.", ["compass_points_to_force_confusion"], skill_tags=["compass_use"], acceptance_rules=acceptance_groups(["compass", "flag", "test compass"], ["shows", "reveals", "lines up with"], ["local", "at that point"], ["field direction", "direction of the field"])) ,
        mcq("M12L1_C2", "Where is the field strongest in a field-line map?", ["where the lines are closest together", "where the page has the most white space", "where the labels are largest", "where the magnet is hidden"], 0, "Closer-spaced lines represent a stronger field.", ["field_lines_as_paths_confusion"], skill_tags=["field_strength"]),
        mcq("M12L1_C3", "Which sentence is strongest?", ["Permanent magnets and current-carrying wires can both create magnetic fields.", "Only permanent magnets can create fields.", "Only batteries can create fields.", "Current destroys magnetic fields when it flows."], 0, "Both magnets and currents belong in the same field story.", ["current_magnetism_separate_confusion"], skill_tags=["electric_magnetic_link"]),
        short("M12L1_C4", "Why is Module 12 not a completely separate world from Module 10?", ["Because moving charges in a current create magnetic fields, so the carrier route already throws a field weave into space.", "Because the current story naturally grows into the magnetic-field story."], "Link moving charge to magnetic field.", ["current_magnetism_separate_confusion"], skill_tags=["electric_magnetic_link"], acceptance_rules=acceptance_groups(["moving charges", "current", "carrier route"], ["create", "throw"], ["magnetic field", "field weave"], ["same story", "not separate", "grows into"])) ,
        mcq("M12L1_C5", "If a compass flag is moved to a different point near a magnet, the reason it may turn is that...", ["the field direction can be different at the new point", "the current in the magnet changed", "compasses always point randomly", "voltage has been induced"], 0, "The field direction changes from point to point.", ["compass_points_to_force_confusion"], skill_tags=["field_direction_map"]),
        mcq("M12L1_C6", "Which picture best matches the field around a straight wire?", ["concentric circles centered on the wire", "parallel lines from one pole to another", "zigzags that show resistance", "one straight arrow through the wire"], 0, "The wire field wraps around the wire in circles.", ["wire_field_direction_confusion"], skill_tags=["wire_field_shape"]),
        short("M12L1_C7", "Why does reversing current reverse the circular field direction around a wire?", ["Because the magnetic field around a wire depends on the current direction, so changing the current direction changes the field direction too.", "Because the surrounding field weave is tied to the direction of carrier motion in the wire."], "Tie the field direction to the current direction.", ["wire_field_direction_confusion"], skill_tags=["wire_field_reversal"], acceptance_rules=acceptance_groups(["reverse", "changing"], ["current direction", "carrier direction"], ["field direction", "field weave"], ["around the wire"])) ,
        mcq("M12L1_C8", "What is the most careful way to use field lines?", ["Use them as a map for field direction and relative strength.", "Treat them as literal wires carrying hidden particles.", "Use them only for transformer turns-ratio questions.", "Ignore compasses because the lines already move."], 0, "They are a map, not a transport path.", ["field_lines_as_paths_confusion"], skill_tags=["field_line_meaning"]),
    ]
    t = [
        mcq("M12L1_M1", "Two diagrams show magnetic field lines. Diagram A has closer line spacing near one pole than Diagram B. The better conclusion is...", ["Diagram A shows a stronger field there.", "Diagram A must have more current everywhere.", "Diagram B has a larger voltage.", "The diagrams cannot say anything about strength."], 0, "Line density is the field-strength clue.", ["field_lines_as_paths_confusion"], skill_tags=["field_strength"]),
        mcq("M12L1_M2", "A straight wire carries current upward. If the current is reversed, what happens to the field around the wire?", ["Its circular direction reverses.", "It becomes a bar-magnet pattern.", "It stays identical.", "It turns into heat flow."], 0, "Wire-field direction depends on current direction.", ["wire_field_direction_confusion"], skill_tags=["wire_field_reversal"]),
        short("M12L1_M3", "A learner says field lines are 'where the magnetic stuff travels.' What should you say instead?", ["I would say field lines are a diagram that shows magnetic field direction and relative strength, not a path for magnetic stuff to travel on.", "I would say the lines are a map of the field, rather than literal moving tracks."], "Correct the field-line picture.", ["field_lines_as_paths_confusion"], skill_tags=["field_line_meaning"], acceptance_rules=acceptance_groups(["field lines"], ["map", "diagram"], ["direction", "strength"], ["not", "rather than"], ["path", "track", "stuff travels"])) ,
        mcq("M12L1_M4", "What does a compass flag actually sample?", ["the local field direction", "the resistance of the wire", "the induced voltage", "the turns ratio"], 0, "A compass flag samples the field direction at one point.", ["compass_points_to_force_confusion"], skill_tags=["compass_use"]),
        short("M12L1_M5", "Why do a permanent magnet and a current-carrying wire both belong in the same lesson?", ["Because both create magnetic fields in space, even though one is a permanent magnet and the other is a current route.", "Because both are sources of magnetic weave, so they belong to one field story."], "Use common-field-source language.", ["current_magnetism_separate_confusion"], skill_tags=["electric_magnetic_link"], acceptance_rules=acceptance_groups(["both", "magnet", "wire", "current"], ["create", "source"], ["magnetic field", "magnetic weave"], ["same lesson", "same story", "linked"])) ,
        mcq("M12L1_M6", "Outside a bar magnet, which direction is the field drawn?", ["from north pole to south pole", "from south pole to north pole", "toward the battery", "toward the larger resistor"], 0, "That is the standard outside-the-magnet direction.", ["field_lines_as_paths_confusion"], skill_tags=["magnet_field_direction"]),
        short("M12L1_M7", "How would you compare the bar-magnet field pattern with the straight-wire field pattern?", ["A bar magnet has a pole-to-pole field pattern, while a straight current-carrying wire has circular field lines around the wire.", "The magnet field loops from north to south outside the magnet, but the wire field wraps in circles around the route."], "Keep the two patterns distinct.", ["wire_field_direction_confusion", "field_lines_as_paths_confusion"], skill_tags=["pattern_compare"], acceptance_rules=acceptance_groups(["bar magnet", "magnet"], ["north", "south", "pole-to-pole"], ["wire", "current-carrying wire"], ["circular", "circles", "wrap around"])) ,
        mcq("M12L1_M8", "Which statement is weakest?", ["Field lines show where matter is forced to travel.", "Field lines show magnetic field direction.", "Closer spacing can mean stronger field.", "A compass can reveal local field direction."], 0, "The field-line map is not a matter-transport story.", ["field_lines_as_paths_confusion"], skill_tags=["field_line_meaning"]),
        short("M12L1_M9", "Why is a compass flag better described as a test probe than as a force meter?", ["Because it tells the direction of the field at that point rather than directly measuring a force size.", "Because its main job is to line up with the local field and reveal direction."], "Keep the probe role precise.", ["compass_points_to_force_confusion"], skill_tags=["compass_use"], acceptance_rules=acceptance_groups(["direction", "field direction", "local field"], ["not", "rather than"], ["force", "force size", "meter"], ["probe", "test compass", "lines up"])) ,
        mcq("M12L1_M10", "Best summary of Lesson 1:", ["Magnets and currents both create magnetic fields that can be mapped by direction and strength.", "Magnetic fields are just hidden current in batteries.", "Only compasses create field lines.", "Field lines replace current and voltage in all problems."], 0, "That keeps the field source and map roles clear.", ["current_magnetism_separate_confusion", "field_lines_as_paths_confusion"], skill_tags=["lesson_summary"]),
    ]
    return lesson_spec(
        "M12_L1",
        "Field Towers and Weave Lines",
        sim(
            "m12_weave_mapper_lab",
            "Weave Mapper lab",
            "Map magnetic fields around a bar magnet and a straight current-carrying wire with compass probes.",
            ["Place compass flags around the source.", "Compare the bar-magnet map with the wire map.", "Reverse the current and compare the changed wire field."],
            ["Explain what field lines show.", "Explain how a compass reveals field direction.", "Compare a permanent-magnet field with a wire field."],
            ["source_type", "field_direction", "field_density", "probe_heading"],
            "Magnetic-field mapping reasoning.",
        ),
        d,
        "The carrier routes from the electricity modules now throw invisible field weave into space, while permanent magnets act like fixed field towers that already fill space with a stable weave.",
        "Before you chase forces or machines, first ask what creates the field and how you would map it with a small probe.",
        [prompt_block("What does a Compass Flag show?", "It shows the local field direction."), prompt_block("What does closer weave spacing mean?", "A stronger field.")],
        [prompt_block("Place a compass around a bar magnet and note how it turns.", "It aligns with the local field direction."), prompt_block("Now switch to a live wire and compare the pattern.", "The wire field wraps in circles around the route.")],
        ["Explain why field lines are maps rather than literal paths.", "Explain how current already links electricity to magnetism."],
        "Use the field map to separate source, direction, and strength before you decide anything about effects.",
        c,
        t,
        contract(
            concept_targets=[
                "Explain what magnetic field lines represent and how compass probes reveal local field direction.",
                "Compare the magnetic field around a bar magnet with the magnetic field around a straight wire.",
                "Use line spacing qualitatively to compare field strength.",
            ],
            core_concepts=[
                "Permanent magnets and current-carrying wires can both create magnetic fields.",
                "Magnetic field lines show field direction and relative strength.",
                "A compass aligns with the local field direction.",
                "Denser field lines represent stronger field regions.",
                "A straight wire produces circular magnetic field lines around itself.",
            ],
            prerequisite_lessons=["M10_L2"],
            misconception_focus=[
                "current_magnetism_separate_confusion",
                "field_lines_as_paths_confusion",
                "compass_points_to_force_confusion",
                "wire_field_direction_confusion",
            ],
            formulas=[relation("line density up -> field strength up", "Closer-spaced field lines indicate a stronger field region.", ["qualitative"], "Use as a field-map reading rule rather than a numerical equation.")],
            representations=[
                representation("field-line diagram", "Shows direction and relative strength of the magnetic field."),
                representation("compass map", "Shows how a local probe reveals field direction point by point."),
                representation("comparison sketch", "Separates bar-magnet and wire-field patterns."),
                representation("words", "Keeps field lines from becoming literal travel paths."),
            ],
            analogy_map=field_weave_map("the class is mapping fields around a bar magnet and a straight wire"),
            worked_examples=[
                worked("A learner points to a dense cluster of field lines and asks what it means.", ["Read the line spacing as a field clue.", "Name the quantity being compared.", "State the conclusion."], "The field is stronger in that region.", "Field-line density is a map cue for relative field strength.", "This gives students a clean way to read magnetic maps before using them in motors or induction."),
                worked("Why does a compass turn when moved to a new point near a magnet?", ["Treat the compass as a local probe.", "Ask what the field direction is at the new point.", "Connect the compass turn to that direction."], "It turns because the local magnetic field direction is different at the new point.", "A compass shows field direction, not hidden current or voltage.", "This helps students trust local field reasoning later."),
                worked("Compare the field around a bar magnet with the field around a straight wire.", ["Name the source in each case.", "Describe the pattern for the magnet.", "Describe the pattern for the wire."], "A bar magnet has a pole-to-pole pattern, while a straight wire has circular field lines around the wire.", "The patterns differ because the field sources differ.", "This is the gateway comparison that keeps the whole module unified."),
                worked("A student says electricity and magnetism are separate because a magnet can work without a battery. What is the better response?", ["Allow the permanent-magnet case.", "Add the current-carrying wire case.", "State the common feature."], "They are linked because both permanent magnets and moving charges can create magnetic fields.", "The module is about field sources, not only about batteries.", "This keeps Module 12 tied to the earlier circuit story without forcing them to be identical."),
            ],
            visual_assets=[visual("m12-l1-field-weave-map", "magnetic_field_map", "Field-weave map", "Shows a bar magnet and a straight wire with compass probes sampling direction and line density.", "Keep the magnet field pattern and the wire field pattern visually separate so students do not merge them.")],
            animation_assets=[animation("m12-l1-compass-sweep", "magnetic_field_map", "Compass sweep", "Shows compass flags turning as they move through different parts of the field map.")],
            simulation_contract=sim_contract(
                "m12-l1-weave-mapper-lab",
                "magnetic_field_map",
                "How do field sources, line direction, and line density work together in a magnetic-field map?",
                "Start with a bar magnet and one compass flag before switching to a straight current-carrying wire.",
                ["Move the probe to different locations and compare its heading.", "Reverse the wire current and compare how the circular field direction changes."],
                "Do not treat field lines as if they were literal travel tracks for matter.",
                "Magnetic fields are mapped by direction and relative strength, and both magnets and currents can be the source.",
                [("source_type", "Field source", "Compares permanent-magnet and current-route field maps."), ("probe_position", "Probe position", "Shows that field direction can change from point to point."), ("current_direction", "Current direction", "Controls the circular field direction around the wire.")],
                [("Compass heading", "Shows the local field direction."), ("Weave density", "Shows the relative field strength at the probe location."), ("Pattern type", "Keeps the bar-magnet map separate from the wire map.")],
            ),
            reflection_prompts=[
                "Why is it important to treat field lines as a map rather than as literal tracks?",
                "How does Lesson 1 already link moving charges to magnetism instead of treating them as separate topics?",
            ],
            mastery_skills=["field_source", "field_line_meaning", "compass_use", "field_strength", "electric_magnetic_link"],
            variation_plan={
                "diagnostic": "Fresh attempts rotate between field-line meaning, compass interpretation, and wire-versus-magnet pattern recognition.",
                "concept_gate": "Concept checks vary between line-density reading, source comparison, and current-direction field reasoning.",
                "mastery": "Mastery mixes map interpretation, misconception correction, and wire-field reversal cases before repeating any prompt.",
            },
            scaffold_support=scaffold(
                "Field lines are a magnetic map, and the first job is to identify the source and the local field direction.",
                "Use compasses and line spacing to reason about direction and strength before thinking about machines or induced current.",
                "If a compass turns at a new location, what field feature changed there?",
                "Do not describe field lines as if they were literal tracks carrying magnetic material around.",
                "A carrier route throws a surrounding weave into space, and a permanent magnet is a built-in field tower doing the same field job without a battery.",
                "Which part of the model plays the role of a local direction probe?",
                [
                    extra_section("Direction first", "A compass tells you which way the field points at one point. Use that local idea before making bigger claims about the whole pattern.", "What does the compass reveal that your eye cannot see directly?"),
                    extra_section("Pattern matters", "A bar magnet and a straight wire do not make the same field shape. Compare the pattern before you compare the strength.", "How does the wire field shape differ from the bar-magnet field shape?"),
                ],
            ),
            visual_clarity_checks=visual_checks("field-map"),
        ),
    )


def electromagnet_lesson() -> Dict[str, Any]:
    d = [
        mcq("M12L2_D1", "A straight current-carrying route produces...", ["circular magnetic field rings around the route", "no magnetic field until a magnet is nearby", "only voltage and no field", "a transformer by itself"], 0, "A current route already creates a field around itself.", ["current_magnetism_separate_confusion", "wire_field_direction_confusion"], skill_tags=["wire_field_shape"]),
        mcq("M12L2_D2", "Wrapping that route into a coil mainly...", ["concentrates and reinforces the field", "destroys the field", "changes current into voltage only", "removes the need for a source"], 0, "Coiling lets the circular field pieces reinforce one another.", ["electromagnet_strength_confusion"], skill_tags=["coil_strengthening"]),
        mcq("M12L2_D3", "A Coil Tower in this module stands for a...", ["solenoid or electromagnet", "permanent bar magnet only", "split-ring commutator", "transformer secondary only"], 0, "A coil tower represents a wound current path acting like an electromagnet.", ["current_magnetism_separate_confusion"], skill_tags=["electromagnet_definition"]),
        mcq("M12L2_D4", "Which change usually makes an electromagnet stronger?", ["more turns on the coil", "less current in the coil", "removing the core while keeping everything else the same", "painting the coil a brighter color"], 0, "More turns reinforce the field.", ["electromagnet_strength_confusion"], skill_tags=["electromagnet_strength"]),
        mcq("M12L2_D5", "Which change also usually makes an electromagnet stronger?", ["larger current", "lower current", "disconnecting the supply", "turning the coil into a mirror"], 0, "Higher current gives a stronger field.", ["electromagnet_strength_confusion"], skill_tags=["electromagnet_strength"]),
        short("M12L2_D6", "Why does adding a soft-iron Core Spine strengthen a coil tower?", ["Because the soft-iron core helps concentrate and strengthen the magnetic field inside the coil.", "Because the core gives the magnetic field an easier path and increases the electromagnet strength."], "Use core-strengthening language.", ["soft_iron_core_confusion"], skill_tags=["core_role"], acceptance_rules=acceptance_groups(["soft iron", "core", "core spine"], ["concentrate", "strengthen", "increase"], ["magnetic field", "electromagnet"])),
        mcq("M12L2_D7", "A solenoid is often compared to a bar magnet because...", ["it has north and south pole behavior", "it has no field outside it", "it uses only permanent magnets and no current", "it can never be switched off"], 0, "A current-carrying coil behaves like a magnet with poles.", ["electromagnet_strength_confusion"], skill_tags=["solenoid_poles"]),
        mcq("M12L2_D8", "If the current through an electromagnet is turned off, the field from the coil...", ["collapses greatly or disappears", "must stay as strong forever", "changes into sound automatically", "becomes a transformer ratio"], 0, "An electromagnet depends on current.", ["electromagnet_strength_confusion"], skill_tags=["current_dependency"]),
        short("M12L2_D9", "Why is an electromagnet already evidence that electricity and magnetism are one linked system?", ["Because the magnetic field is being created by electric current in the coil.", "Because moving charge in the coil produces the magnetic effect."], "Tie the field directly to current.", ["current_magnetism_separate_confusion"], skill_tags=["electric_magnetic_link"], acceptance_rules=acceptance_groups(["current", "moving charge", "coil"], ["creates", "produces"], ["magnetic field", "magnetic effect"], ["linked", "same system", "not separate"])),
        mcq("M12L2_D10", "Best first move when asked to strengthen an electromagnet:", ["check current, turn count, and whether a soft-iron core is present", "look for the nearest battery label only", "count the field lines by hand and ignore the coil", "replace it with a resistor"], 0, "Those are the main strengthening levers at this level.", ["electromagnet_strength_confusion", "soft_iron_core_confusion"], skill_tags=["prediction_habit"]),
    ]
    c = [
        short("M12L2_C1", "Why is a coil stronger than a single straight wire for magnetic effect?", ["Because the circular fields from the turns reinforce each other and make a stronger combined field.", "Because winding the route into many turns concentrates the field into one stronger pattern."], "Use reinforcement language.", ["electromagnet_strength_confusion"], skill_tags=["coil_strengthening"], acceptance_rules=acceptance_groups(["turns", "coil"], ["reinforce", "add together", "concentrate"], ["field", "magnetic field"], ["stronger"])),
        mcq("M12L2_C2", "Which combination should give the strongest electromagnet?", ["many turns, large current, soft-iron core", "few turns, tiny current, no core", "many turns, no current", "no turns, large color label"], 0, "Stack the three strengthening factors together.", ["electromagnet_strength_confusion", "soft_iron_core_confusion"], skill_tags=["electromagnet_strength"]),
        mcq("M12L2_C3", "What is the cleanest way to explain a soft-iron core at this stage?", ["It strengthens and concentrates the magnetic field made by the coil.", "It stores charge for the coil.", "It makes the battery voltage larger directly.", "It replaces the need for current."], 0, "A soft-iron core strengthens the electromagnet field.", ["soft_iron_core_confusion"], skill_tags=["core_role"]),
        short("M12L2_C4", "Why is 'the core stores current' a weak statement?", ["Because the core strengthens the magnetic field, but the current is still in the wire of the coil.", "Because the soft-iron core is part of the field-strength story, not the place where the current is stored."], "Separate the core role from the current route.", ["soft_iron_core_confusion"], skill_tags=["core_role"], acceptance_rules=acceptance_groups(["core", "soft iron"], ["strengthens", "concentrates"], ["magnetic field"], ["current", "wire", "coil"], ["not", "rather than"], ["stored", "stores current"])),
        mcq("M12L2_C5", "What happens to the poles of a solenoid if the current direction is reversed?", ["the north and south poles swap", "nothing changes at all", "the coil stops having a field forever", "it becomes a generator"], 0, "Changing current direction changes the magnetic polarity.", ["wire_field_direction_confusion"], skill_tags=["polarity_reversal"]),
        short("M12L2_C6", "Why can an electromagnet be useful when you want magnetic lifting that can be turned on and off?", ["Because its magnetic field depends on the current, so switching the current changes the magnetic strength.", "Because the magnetism can be controlled by controlling the current in the coil."], "Use current-control language.", ["electromagnet_strength_confusion"], skill_tags=["current_dependency"], acceptance_rules=acceptance_groups(["current"], ["control", "switch on and off", "depends on"], ["magnetic field", "magnetism", "strength"])),
        mcq("M12L2_C7", "Which factor does not directly strengthen the electromagnet in this model?", ["the paint color of the coil", "the turn count", "the current", "the soft-iron core"], 0, "Only the electrical and core factors matter here.", ["electromagnet_strength_confusion"], skill_tags=["electromagnet_strength"]),
        short("M12L2_C8", "How is a solenoid like a bar magnet?", ["It creates a field pattern with north and south pole behavior.", "Its field is organized into a magnet-like pattern rather than remaining just a loose ring around one straight wire."], "Keep the pole pattern explicit.", ["electromagnet_strength_confusion"], skill_tags=["solenoid_poles"], acceptance_rules=acceptance_groups(["north", "south", "poles"], ["field pattern", "magnet-like"], ["solenoid", "coil"])),
    ]
    t = [
        mcq("M12L2_M1", "Which design should make the strongest crane electromagnet?", ["high current, many turns, soft-iron core", "high current, no coil, no core", "many turns but disconnected from the source", "soft-iron core with no wire"], 0, "Strength comes from current, turns, and core together.", ["electromagnet_strength_confusion", "soft_iron_core_confusion"], skill_tags=["electromagnet_strength"]),
        short("M12L2_M2", "A classmate says the core is where the current lives. What is the better explanation?", ["The current flows in the coil wire, while the soft-iron core strengthens the magnetic field made by that current.", "The core does not carry the main current story; it boosts the electromagnet field inside the coil."], "Separate current path from core role.", ["soft_iron_core_confusion"], skill_tags=["core_role"], acceptance_rules=acceptance_groups(["current"], ["coil", "wire"], ["core", "soft iron"], ["strengthens", "boosts"], ["magnetic field"])),
        mcq("M12L2_M3", "If the current in a solenoid is reversed, what is the strongest prediction?", ["its pole orientation reverses", "it loses all field permanently", "its resistance disappears", "it must become a transformer"], 0, "Current direction controls magnetic polarity.", ["wire_field_direction_confusion"], skill_tags=["polarity_reversal"]),
        short("M12L2_M4", "Why do more turns usually strengthen the electromagnet?", ["Because the magnetic field contributions from the turns reinforce each other.", "Because each extra turn adds to the combined field of the coil."], "Use reinforcement rather than mystery language.", ["electromagnet_strength_confusion"], skill_tags=["coil_strengthening"], acceptance_rules=acceptance_groups(["more turns", "extra turns"], ["reinforce", "add", "combine"], ["field", "magnetic field"], ["stronger"])),
        mcq("M12L2_M5", "Which statement is strongest?", ["An electromagnet is a magnetic field created and controlled by electric current.", "An electromagnet is a permanent magnet that no longer needs current.", "An electromagnet stores voltage inside an iron core.", "An electromagnet only works if a generator is already attached."], 0, "It is current-created and current-controlled magnetism.", ["current_magnetism_separate_confusion", "electromagnet_strength_confusion"], skill_tags=["electromagnet_definition"]),
        short("M12L2_M6", "Why can turning off the current make a crane electromagnet let go of scrap metal?", ["Because the magnetic field of the electromagnet depends on the current and weakens greatly when the current is removed.", "Because switching off the current removes the field that was providing the lifting effect."], "Keep the current dependence explicit.", ["electromagnet_strength_confusion"], skill_tags=["current_dependency"], acceptance_rules=acceptance_groups(["switch off", "turn off"], ["current"], ["magnetic field", "magnetism"], ["weakens", "disappears", "removed"])),
        mcq("M12L2_M7", "Which comparison is correct for otherwise similar coils?", ["more turns gives a stronger electromagnet than fewer turns", "fewer turns always gives the stronger field", "the core removes the need for turns", "turn count cannot matter"], 0, "Turn count is one of the main strength controls.", ["electromagnet_strength_confusion"], skill_tags=["electromagnet_strength"]),
        short("M12L2_M8", "How does Lesson 2 deepen the link between circuits and magnetism?", ["It shows that a current in a wire or coil creates the field, and a coil can become a controllable electromagnet.", "It turns the current route into a field source, so the electrical story now has magnetic consequences."], "Make the current-to-field link explicit.", ["current_magnetism_separate_confusion"], skill_tags=["electric_magnetic_link"], acceptance_rules=acceptance_groups(["current", "wire", "coil"], ["creates", "becomes"], ["field", "magnetic field", "electromagnet"], ["link", "consequence", "same story"])),
        mcq("M12L2_M9", "Best first question when an electromagnet seems too weak:", ["Can I increase current, add turns, or improve the core?", "Can I rename the poles?", "Can I replace the field with light?", "Can I ignore the coil geometry?"], 0, "Those are the first physical levers to inspect.", ["electromagnet_strength_confusion", "soft_iron_core_confusion"], skill_tags=["prediction_habit"]),
        short("M12L2_M10", "Why is a solenoid better than a single straight wire for making a practical lifting magnet?", ["Because the coil concentrates and strengthens the magnetic field into a magnet-like pattern with poles.", "Because the many turns make a stronger, more organized magnetic effect than one straight route."], "Use concentrated-field language.", ["electromagnet_strength_confusion"], skill_tags=["coil_strengthening"], acceptance_rules=acceptance_groups(["coil", "many turns", "solenoid"], ["concentrate", "strengthen", "organized"], ["magnetic field", "magnetic effect"], ["poles", "magnet-like pattern"])),
    ]
    return lesson_spec(
        "M12_L2",
        "Carrier Routes, Coil Towers, and Electromagnets",
        sim(
            "m12_core_boost_lab",
            "Core Boost lab",
            "Strengthen a current-produced magnetic field by changing current, turns, and the soft-iron core.",
            ["Start with one coil and no core.", "Add more turns and compare the field.", "Insert the core and compare the strength again."],
            ["Explain why a solenoid behaves like a magnet.", "Explain how turns, current, and core change electromagnet strength.", "Explain why the field can be switched on and off."],
            ["coil_turns", "coil_current", "core_state", "field_strength"],
            "Electromagnet-strength reasoning.",
        ),
        d,
        "A straight carrier route already throws circular weave rings into space. Wind that route into a Coil Tower, and the rings reinforce into a stronger field that can act like a magnet.",
        "When an electromagnet is weak, do not guess. Check the three levers that matter here: current, turn count, and core.",
        [prompt_block("What makes the field around a coil stronger?", "More turns, more current, and a soft-iron core."), prompt_block("Why can an electromagnet be switched off?", "Its field depends on current.")],
        [prompt_block("Increase the turn count first and compare the field readout.", "The field should strengthen because the turns reinforce one another."), prompt_block("Now insert the soft-iron core and compare again.", "The field becomes more concentrated and stronger.")],
        ["Explain why a coil is stronger than a single straight wire.", "Explain why an electromagnet can be controlled by switching current."],
        "Use the field-weave language to keep the strengthening story physical: current creates the field, turns reinforce it, and the core helps concentrate it.",
        c,
        t,
        contract(
            concept_targets=[
                "Explain why a coil strengthens the magnetic field compared with a single straight wire.",
                "Explain how current, turns, and soft-iron cores affect electromagnet strength.",
                "Explain why a solenoid behaves like a controllable magnet.",
            ],
            core_concepts=[
                "A current-carrying wire already creates a magnetic field.",
                "Wrapping the wire into a coil lets the field contributions reinforce one another.",
                "A solenoid behaves like a magnet with north and south pole behavior.",
                "Electromagnet strength increases with current, turn count, and a soft-iron core.",
                "An electromagnet can be turned on and off because the field depends on the current.",
            ],
            prerequisite_lessons=["M12_L1", "M10_L2"],
            misconception_focus=[
                "current_magnetism_separate_confusion",
                "wire_field_direction_confusion",
                "electromagnet_strength_confusion",
                "soft_iron_core_confusion",
            ],
            formulas=[
                relation("current up / turns up / core added -> electromagnet strength up", "Field strength increases when the coil is reinforced more strongly.", ["qualitative"], "Use as a strengthening rule rather than a numerical law."),
                relation("current reversed -> pole orientation reversed", "Changing current direction changes the magnetic polarity of the coil.", ["qualitative"], "Use when reasoning about solenoid poles."),
            ],
            representations=[
                representation("coil diagram", "Shows turns reinforcing one another."),
                representation("pole sketch", "Shows the solenoid acting like a magnet."),
                representation("comparison table", "Separates current, turns, and core as different strengthening levers."),
                representation("words", "Keeps the field created by current visible."),
            ],
            analogy_map=field_weave_map("the class is strengthening a coil-produced field with turns, current, and a soft-iron core"),
            worked_examples=[
                worked("A learner adds turns to a coil and asks why the electromagnet becomes stronger.", ["Start with the field around one turn.", "Add the fields from many turns.", "State the combined effect."], "The turns reinforce one another and make the field stronger.", "Many turns add their magnetic effects together in a concentrated region.", "This keeps the strength story grounded in field addition rather than magic."),
                worked("Why does a soft-iron core make an electromagnet stronger?", ["Separate the current path from the core.", "State the core's magnetic job.", "Give the field-based conclusion."], "The soft-iron core strengthens and concentrates the magnetic field created by the coil.", "The current stays in the wire, but the core helps the field become stronger.", "This directly blocks the idea that the core stores current."),
                worked("Compare a permanent magnet with an electromagnet.", ["Ask what creates the field in each case.", "Ask whether it can be switched off easily.", "State the comparison."], "A permanent magnet has its own built-in field, while an electromagnet creates its field from current and can be controlled by switching that current.", "The sources differ, but both are field sources.", "This keeps the module coherent without flattening the differences."),
                worked("A crane needs a stronger lifting magnet. Which three adjustments should you consider first?", ["Check the current.", "Check the turn count.", "Check whether a soft-iron core is present."], "Increase current, increase turns, and use an appropriate soft-iron core.", "Those are the main school-level strength controls for an electromagnet.", "This frames electromagnet design as controlled reasoning, not guesswork."),
            ],
            visual_assets=[visual("m12-l2-coil-tower", "electromagnet", "Coil tower", "Shows a straight wire field becoming a reinforced coil field with a soft-iron core option.", "Keep current, turns, poles, and core role readable as separate labels.")],
            animation_assets=[animation("m12-l2-core-boost", "electromagnet", "Core boost", "Shows field strengthening as turns and current increase and then a core is inserted.")],
            simulation_contract=sim_contract(
                "m12-l2-core-boost-lab",
                "electromagnet",
                "How do current, turn count, and a soft-iron core change the strength of a coil-produced magnetic field?",
                "Start with a current-carrying coil with no core and a modest turn count.",
                ["Increase the current while holding turns fixed.", "Increase the turn count while holding current fixed.", "Insert and remove the soft-iron core and compare the field strength."],
                "Do not talk as if the core stores current or replaces the need for current.",
                "A coil-produced magnetic field becomes stronger when the current or turn count increases and when a soft-iron core is used.",
                [("coil_current", "Coil current", "Sets how strongly the current creates magnetic weave."), ("turn_count", "Turn count", "Shows how field contributions from many turns reinforce each other."), ("core_state", "Core spine", "Shows the strengthening role of soft iron.")],
                [("Field strength", "Compares how strong the electromagnet is."), ("Pole pattern", "Shows the magnet-like behavior of the solenoid."), ("Control note", "Explains why switching current can switch the electromagnet.")],
            ),
            reflection_prompts=[
                "Why is it not enough just to say that a coil 'makes magnetism' without explaining current, turns, and the core?",
                "How does Lesson 2 make the electricity-to-magnetism link more concrete than Lesson 1?",
            ],
            mastery_skills=["electromagnet_definition", "coil_strengthening", "electromagnet_strength", "core_role", "current_dependency"],
            variation_plan={
                "diagnostic": "Fresh attempts rotate between coil meaning, strength-factor recognition, and current-dependence stems.",
                "concept_gate": "Concept checks vary between turns reasoning, core reasoning, polarity reversal, and on-off control.",
                "mastery": "Mastery mixes design choices, misconception correction, and current-turn-core comparisons before repeating any prompt.",
            },
            scaffold_support=scaffold(
                "Current creates the field, and coils plus cores organize that field into a stronger electromagnet.",
                "When you want a stronger electromagnet, inspect current, turns, and the core before saying anything else.",
                "Which change should matter more here: a bigger current, more turns, or a brighter paint color?",
                "Do not describe the core as if it were where the current is stored.",
                "A single route throws circular weave rings into space, but a coil tower lets many rings reinforce into one stronger magnetic pattern.",
                "What three levers can you change to strengthen the coil tower?",
                [
                    extra_section("Turns reinforce", "Every extra turn contributes to the overall field, so a coil can be much stronger than one straight section alone.", "Why is a many-turn coil stronger than one straight route?"),
                    extra_section("Core helps the field", "A soft-iron core strengthens the magnetic field made by the coil, but the current is still in the wire.", "What does the core strengthen, and what does it not store?"),
                ],
            ),
            visual_clarity_checks=visual_checks("electromagnet"),
        ),
    )


def side_kick_lesson() -> Dict[str, Any]:
    d = [
        mcq("M12L3_D1", "A current-carrying conductor placed across a magnetic field can experience a...", ["sideways force", "voltage that always increases forward speed", "temperature drop only", "turns ratio"], 0, "A magnetic field can push a current-carrying conductor sideways.", ["magnetic_force_forward_confusion"], skill_tags=["force_on_conductor"]),
        mcq("M12L3_D2", "That magnetic side-kick is best described as...", ["perpendicular to both the field and the current direction", "always in the same direction as the current", "always along the field line", "independent of field direction"], 0, "The magnetic force is sideways to both current and field.", ["magnetic_force_forward_confusion"], skill_tags=["force_geometry"]),
        mcq("M12L3_D3", "If the current direction is reversed while the field stays the same, the force direction...", ["reverses", "stays identical", "becomes zero automatically", "changes into voltage"], 0, "Reversing current reverses the magnetic force direction.", ["force_direction_reversal_confusion"], skill_tags=["reverse_current_force"]),
        mcq("M12L3_D4", "If the magnetic field direction is reversed while the current stays the same, the force direction...", ["reverses", "stays identical", "always becomes upward", "must become heat"], 0, "Reversing the field also reverses the force direction.", ["force_direction_reversal_confusion"], skill_tags=["reverse_field_force"]),
        mcq("M12L3_D5", "If a conductor is parallel to the magnetic field, the sideways force is usually...", ["zero or minimal", "largest possible", "equal to the voltage", "the same as in every orientation"], 0, "No perpendicular cutting means no sideways magnetic push in this simple model.", ["magnetic_force_forward_confusion"], skill_tags=["parallel_case"]),
        short("M12L3_D6", "Why is the word side-kick better than forward shove here?", ["Because the magnetic force acts sideways to the current and the field, rather than pushing the conductor forward along either one.", "Because the force is perpendicular, not a push along the conductor's motion or the field lines."], "Keep the force geometry explicit.", ["magnetic_force_forward_confusion"], skill_tags=["force_geometry"], acceptance_rules=acceptance_groups(["sideways", "perpendicular"], ["force"], ["current", "conductor"], ["field"], ["not", "rather than"], ["forward", "along"])),
        mcq("M12L3_D7", "Which change should usually increase the magnetic force on a conductor in this lesson?", ["a stronger field", "a weaker field", "removing the current", "making the conductor parallel to the field"], 0, "A stronger field gives a bigger side-kick.", ["magnetic_force_forward_confusion"], skill_tags=["force_size"]),
        mcq("M12L3_D8", "Which other change should usually increase that force?", ["larger current", "smaller current", "less field", "zero field"], 0, "More current means a larger magnetic effect on the conductor.", ["magnetic_force_forward_confusion"], skill_tags=["force_size"]),
        short("M12L3_D9", "What does Fleming's left-hand rule help you work out?", ["It helps you determine the direction of force, field, and current in motor-effect situations.", "It is a direction rule for the force on a current-carrying conductor in a magnetic field."], "Tie the rule to direction, not magnitude.", ["force_direction_reversal_confusion"], skill_tags=["left_hand_rule"], acceptance_rules=acceptance_groups(["Fleming", "left-hand rule"], ["direction"], ["force"], ["field"], ["current", "conductor"])),
        mcq("M12L3_D10", "Best first question when reading a side-kick diagram:", ["Which way do the field and current point, and are they crossing?", "How bright is the field?", "How many turns are in the transformer?", "Which quantity is energy per charge?"], 0, "Direction and relative orientation come first.", ["magnetic_force_forward_confusion"], skill_tags=["prediction_habit"]),
    ]
    c = [
        short("M12L3_C1", "Why can a magnetic field steer a conductor without simply speeding it up along the field line?", ["Because the magnetic force is perpendicular to the field and the current, so it changes direction rather than acting like a forward push.", "Because the field gives a sideways force rather than a shove along the field line."], "Use perpendicular-force language.", ["magnetic_force_forward_confusion"], skill_tags=["force_geometry"], acceptance_rules=acceptance_groups(["perpendicular", "sideways"], ["force"], ["field"], ["current", "conductor"], ["changes direction", "steer"], ["not", "rather than"], ["forward", "along"])),
        mcq("M12L3_C2", "A conductor crossing a field with more current should feel...", ["a larger sideways force", "no magnetic force", "a smaller force automatically", "a transformer effect instead"], 0, "More current usually strengthens the magnetic side-kick.", ["magnetic_force_forward_confusion"], skill_tags=["force_size"]),
        mcq("M12L3_C3", "If both the current and the field are reversed together, the force direction on the conductor is...", ["unchanged overall", "reversed twice into zero", "always upward", "undefined"], 0, "Reversing both together keeps the sideways relationship the same.", ["force_direction_reversal_confusion"], skill_tags=["double_reversal"]),
        short("M12L3_C4", "Why does a conductor parallel to the field not get the same side-kick as one crossing the field?", ["Because the magnetic effect depends on the current cutting across the field, and a parallel conductor is not crossing the field in the needed sideways way.", "Because there is no effective cross-field geometry to create the sideways force when current and field are parallel."], "Use cross-field geometry language.", ["magnetic_force_forward_confusion"], skill_tags=["parallel_case"], acceptance_rules=acceptance_groups(["parallel"], ["field"], ["not crossing", "no cross-field", "no perpendicular"], ["sideways force", "force"])),
        mcq("M12L3_C5", "What is the main job of Fleming's left-hand rule here?", ["to predict the direction of the motor-effect force", "to calculate transformer voltage", "to prove the field-line spacing", "to find the power loss in a cable"], 0, "It is a direction rule for the motor effect.", ["force_direction_reversal_confusion"], skill_tags=["left_hand_rule"]),
        short("M12L3_C6", "How does Lesson 3 deepen the field story from Lessons 1 and 2?", ["It shows that the field is not just something to map; it can also exert a sideways force on a current-carrying route.", "It turns the field map into an interaction rule by showing how a field can push a current-carrying conductor."], "Map becomes interaction.", ["current_magnetism_separate_confusion", "magnetic_force_forward_confusion"], skill_tags=["field_interaction"], acceptance_rules=acceptance_groups(["field"], ["push", "force", "sideways"], ["current-carrying conductor", "route"], ["not just", "more than"], ["map", "interaction"])),
        mcq("M12L3_C7", "Which statement is strongest?", ["Reversing either the current or the field reverses the force.", "Reversing current leaves force unchanged always.", "Reversing the field removes current completely.", "Force direction is unrelated to field direction."], 0, "Either single reversal flips the force direction.", ["force_direction_reversal_confusion"], skill_tags=["reverse_current_force"]),
        short("M12L3_C8", "Why is 'magnetic fields push charges forward along the lines' a weak statement?", ["Because the magnetic force is sideways to the motion and the field, not a push forward along the field lines.", "Because field lines show direction of the field, but the magnetic force on moving charge is perpendicular to that direction."], "Keep field direction and force direction distinct.", ["magnetic_force_forward_confusion", "field_lines_as_paths_confusion"], skill_tags=["force_geometry"], acceptance_rules=acceptance_groups(["magnetic force"], ["sideways", "perpendicular"], ["field lines", "field direction"], ["not", "rather than"], ["forward", "along"])),
    ]
    t = [
        mcq("M12L3_M1", "A conductor crosses a magnetic field. If only the current is reversed, the force...", ["reverses direction", "stays the same", "becomes zero automatically", "turns into induced emf"], 0, "One reversal flips the force direction.", ["force_direction_reversal_confusion"], skill_tags=["reverse_current_force"]),
        mcq("M12L3_M2", "If only the magnetic field is reversed, the force...", ["reverses direction", "stays the same", "must increase", "vanishes only if the current doubles"], 0, "Field reversal also reverses the force.", ["force_direction_reversal_confusion"], skill_tags=["reverse_field_force"]),
        short("M12L3_M3", "A learner says the field pushes the wire forward because the field line points that way. What should you say?", ["I would say the magnetic force is sideways to both the current and the field, so the wire is not simply pushed forward along the field line.", "I would say field-line direction and force direction are different ideas in the motor effect."], "Separate field direction from force direction.", ["magnetic_force_forward_confusion", "field_lines_as_paths_confusion"], skill_tags=["force_geometry"], acceptance_rules=acceptance_groups(["force"], ["sideways", "perpendicular"], ["current"], ["field", "field line"], ["not", "rather than"], ["forward", "along"])),
        mcq("M12L3_M4", "Which orientation gives the least sideways magnetic force in this simple lesson?", ["conductor parallel to the field", "conductor crossing the field strongly", "conductor in a stronger field", "conductor with larger current"], 0, "Parallel orientation gives no effective cross-field push here.", ["magnetic_force_forward_confusion"], skill_tags=["parallel_case"]),
        short("M12L3_M5", "Why can a magnetic field change direction of motion without directly doing the same job as a battery?", ["Because the battery gives energy per charge, while the magnetic field mainly changes direction by exerting a sideways force.", "Because the magnetic field steers current-carrying conductors rather than acting like the voltage source."], "Separate source and field jobs.", ["magnetic_force_forward_confusion"], skill_tags=["field_interaction"], acceptance_rules=acceptance_groups(["battery", "source", "voltage"], ["energy per charge", "source job"], ["magnetic field"], ["sideways force", "steer", "change direction"], ["not", "rather than"])),
        mcq("M12L3_M6", "Which pair of changes should make the side-kick larger?", ["stronger field and larger current", "weaker field and smaller current", "parallel conductor and zero current", "less field and less current"], 0, "Both stronger field and larger current increase the force at this level.", ["magnetic_force_forward_confusion"], skill_tags=["force_size"]),
        short("M12L3_M7", "What does Fleming's left-hand rule help you keep track of in a motor-effect diagram?", ["It helps keep the directions of field, current, and force consistent.", "It is a direction-check tool for the magnetic force on a current-carrying conductor."], "Use it as a direction-check rule.", ["force_direction_reversal_confusion"], skill_tags=["left_hand_rule"], acceptance_rules=acceptance_groups(["Fleming", "left-hand rule"], ["direction"], ["field"], ["current"], ["force"])),
        mcq("M12L3_M8", "If both field and current are reversed together, the overall force direction is...", ["unchanged", "reversed", "always zero", "random"], 0, "The sideways relationship is preserved when both are reversed.", ["force_direction_reversal_confusion"], skill_tags=["double_reversal"]),
        short("M12L3_M9", "Why is the phrase 'crossing the field' useful in this lesson?", ["Because the magnetic side-kick depends on the current direction being across the field rather than parallel to it.", "Because cross-field geometry helps explain when the force is strong, weak, or zero."], "Keep the geometry visible in words.", ["magnetic_force_forward_confusion"], skill_tags=["parallel_case"], acceptance_rules=acceptance_groups(["crossing", "across"], ["field"], ["sideways force", "magnetic force"], ["parallel"], ["strong", "weak", "zero"])),
        mcq("M12L3_M10", "Best summary of Lesson 3:", ["A magnetic field can exert a sideways force on a current-carrying conductor, and the force direction depends on both field and current direction.", "Magnetic fields always push conductors straight ahead.", "Only permanent magnets can exert forces on wires.", "The force story belongs only to transformers."], 0, "This summary keeps the geometry and reversal ideas together.", ["magnetic_force_forward_confusion", "force_direction_reversal_confusion"], skill_tags=["lesson_summary"]),
    ]
    return lesson_spec(
        "M12_L3",
        "Side-Kicks on Current-Carrying Routes",
        sim(
            "m12_side_kick_lab",
            "Side-Kick lab",
            "Predict the direction and relative size of the force on a current-carrying conductor in a magnetic field.",
            ["Start with a conductor crossing the field.", "Reverse the current only.", "Reverse the field and compare again."],
            ["Explain why the magnetic force is sideways.", "Predict force-direction changes when current or field reverses.", "Explain why parallel orientation gives little or no side-kick."],
            ["field_strength", "current_direction", "field_direction", "force_direction"],
            "Motor-effect force reasoning.",
        ),
        d,
        "The field weave is no longer just a map. When a current-carrying route cuts across it, the route feels a side-kick that points sideways to both the field and the carrier flow.",
        "Before you guess a force direction, identify the field direction, the current direction, and whether the conductor is really crossing the field.",
        [prompt_block("What does the side-kick stand for?", "The magnetic force on a current-carrying conductor."), prompt_block("What happens if current reverses?", "The force direction reverses.")],
        [prompt_block("Start with current crossing the field and note the force arrow.", "The side-kick should be sideways, not forward."), prompt_block("Now make the conductor parallel to the field.", "The sideways force should collapse greatly or disappear.")],
        ["Explain why the force is sideways rather than forward.", "Explain why reversing current or field changes the force direction."],
        "This lesson is about geometry as much as direction. If the current is not crossing the field, the side-kick story changes sharply.",
        c,
        t,
        contract(
            concept_targets=[
                "Explain the magnetic force on a current-carrying conductor as a sideways force in a magnetic field.",
                "Predict how force direction changes when current or field direction changes.",
                "Explain why the conductor orientation relative to the field matters.",
            ],
            core_concepts=[
                "A magnetic field can exert a force on a current-carrying conductor.",
                "The magnetic force is perpendicular to both the field and the current direction.",
                "Reversing the current reverses the force direction.",
                "Reversing the magnetic field reverses the force direction.",
                "The magnetic side-kick is largest when the conductor crosses the field and smallest when it is parallel.",
            ],
            prerequisite_lessons=["M12_L1", "M12_L2", "M10_L2"],
            misconception_focus=[
                "magnetic_force_forward_confusion",
                "force_direction_reversal_confusion",
                "field_lines_as_paths_confusion",
            ],
            formulas=[
                relation("stronger field / larger current -> larger force", "The magnetic side-kick grows when the magnetic interaction is stronger.", ["qualitative"], "Use qualitatively at this level."),
                relation("current reversed or field reversed -> force reversed", "Single reversals flip the force direction.", ["qualitative"], "Use in direction-prediction tasks."),
            ],
            representations=[
                representation("force diagram", "Shows field, current, and force as three distinct directional ideas."),
                representation("left-hand rule sketch", "Supports consistent direction prediction."),
                representation("orientation comparison", "Compares crossing and parallel cases."),
                representation("words", "Keeps the force from being mistaken for a forward shove."),
            ],
            analogy_map=field_weave_map("the class is predicting side-kick direction on a conductor that crosses a magnetic field"),
            worked_examples=[
                worked("A conductor carries current across a field. What should you predict first?", ["Identify the field direction.", "Identify the current direction.", "Use the side-kick rule to predict the force direction."], "Predict the force direction from the field-current geometry first.", "Direction comes from geometry before you talk about strength.", "This trains the habit needed for motors."),
                worked("Why does reversing the current reverse the force?", ["Keep the field fixed.", "Change the current direction only.", "State the result."], "The force reverses because the magnetic interaction depends on the current direction relative to the field.", "One directional input changed, so the force direction flips.", "This is the cleanest entry point to reversal reasoning."),
                worked("Why is a parallel conductor a weak case for side-kick force?", ["Check whether the conductor is crossing the field.", "Notice the lack of cross-field geometry.", "State the conclusion."], "It does not get the same sideways force because it is not cutting across the field in the needed way.", "The magnetic force story depends on the conductor crossing the field.", "This prevents the idea that all magnetic forces are automatic and identical."),
                worked("A learner says the field pushes the wire forward because the field line points that way. What is the correction?", ["Keep field direction and force direction separate.", "State the perpendicular-force rule.", "Explain the better picture."], "The magnetic force is sideways to the field and current, not a forward push along the line.", "Field lines show field direction, but the force direction is a different geometric result.", "This blocks one of the most persistent misconceptions in the module."),
            ],
            visual_assets=[visual("m12-l3-side-kick", "motor_force", "Side-kick", "Shows field direction, current direction, and force direction as three separate directional ideas.", "Keep the field arrow, current arrow, and side-kick arrow visually distinct.")],
            animation_assets=[animation("m12-l3-force-reversal", "motor_force", "Force reversal", "Shows the force reversing when the current or the field is reversed.")],
            simulation_contract=sim_contract(
                "m12-l3-side-kick-lab",
                "motor_force",
                "How do field direction, current direction, and conductor orientation decide the magnetic side-kick?",
                "Start with a conductor clearly crossing the field so the side-kick is easy to see.",
                ["Reverse the current while holding the field fixed.", "Reverse the field while holding the current fixed.", "Rotate the conductor toward the parallel case and compare the force size."],
                "Do not describe the magnetic force as a forward shove along the field line.",
                "The magnetic field gives a sideways force whose direction depends on both field and current direction.",
                [("field_direction", "Field direction", "One of the two main direction inputs."), ("current_direction", "Current direction", "The other main direction input."), ("conductor_angle", "Conductor angle", "Shows why crossing matters for the side-kick.")],
                [("Force direction", "Shows the sideways magnetic force."), ("Force size clue", "Shows how crossing versus parallel geometry changes the force."), ("Rule cue", "Keeps the left-hand-rule direction story visible.")],
            ),
            reflection_prompts=[
                "Why is it stronger to talk about a side-kick than about a forward shove in Lesson 3?",
                "How does the force-direction story depend on geometry as well as on the existence of a field?",
            ],
            mastery_skills=["force_on_conductor", "force_geometry", "reverse_current_force", "parallel_case", "left_hand_rule"],
            variation_plan={
                "diagnostic": "Fresh attempts rotate between force-direction meaning, reversal cases, and orientation cases.",
                "concept_gate": "Concept checks vary between left-hand-rule use, parallel-case reasoning, and field-versus-force distinction.",
                "mastery": "Mastery mixes direction changes, misconception correction, and size comparisons before repeating any prompt.",
            },
            scaffold_support=scaffold(
                "A magnetic field can push a current-carrying conductor sideways, and the direction comes from the field-current geometry.",
                "Ask how the conductor sits in the field and what happens when either directional input is reversed.",
                "If the field stays fixed but the current reverses, what should the side-kick do?",
                "Do not let the field-line direction trick you into imagining a forward shove.",
                "The route is crossing a field weave and getting kicked sideways, not being accelerated along the weave like a sled on rails.",
                "What must you identify before predicting the side-kick direction?",
                [
                    extra_section("Crossing matters", "A conductor that strongly crosses the field gets the clearest side-kick, while a parallel conductor gives a weak or zero case in this model.", "Why is the parallel case weaker?"),
                    extra_section("Single reversals flip the force", "Changing either the field direction or the current direction flips the force direction. That is a reliable reasoning move for motor-effect questions.", "What happens if you reverse only one of the two direction inputs?"),
                ],
            ),
            visual_clarity_checks=visual_checks("force-direction"),
        ),
    )


def motor_lesson() -> Dict[str, Any]:
    d = [
        mcq("M12L4_D1", "A Spin Frame in this module stands for a...", ["motor coil", "permanent magnet only", "transformer core only", "compass flag"], 0, "A spin frame is the turning motor coil.", ["motor_effect_vs_induction_confusion"], skill_tags=["motor_definition"]),
        mcq("M12L4_D2", "Why can a current-carrying coil in a magnetic field start to turn?", ["Opposite sides of the coil feel opposite magnetic forces, creating a turning effect.", "Because the field line pulls the whole coil forward equally.", "Because a transformer ratio appears automatically.", "Because the coil becomes a battery."], 0, "Opposite side-kicks produce torque on the loop.", ["motor_effect_vs_induction_confusion", "magnetic_force_forward_confusion"], skill_tags=["torque_cause"]),
        mcq("M12L4_D3", "The motor effect is best described as...", ["a turning version of the magnetic force on current-carrying conductors", "a kind of transformer action", "heat transfer in a wire", "static induction from a fixed field"], 0, "The motor effect is the force-on-conductor idea arranged to cause rotation.", ["motor_effect_vs_induction_confusion"], skill_tags=["motor_effect"]),
        short("M12L4_D4", "Why do opposite forces on opposite sides of the coil cause turning instead of simple sideways motion?", ["Because the equal and opposite side-kicks act on different sides of the loop and create a turning moment.", "Because the forces form a couple, producing torque on the coil."], "Use turning-moment language.", ["motor_effect_vs_induction_confusion"], skill_tags=["torque_cause"], acceptance_rules=acceptance_groups(["opposite forces", "side-kicks"], ["different sides", "opposite sides"], ["turning moment", "torque", "couple"], ["coil", "loop"])),
        mcq("M12L4_D5", "What is the main job of the split-ring commutator in a d.c. motor?", ["to reverse the coil current each half-turn so the turning stays in the same overall direction", "to step voltage up for transmission", "to remove the magnetic field completely", "to make the coil a permanent magnet"], 0, "The commutator flips current at the right time to sustain rotation.", ["commutator_role_confusion"], skill_tags=["commutator_role"]),
        mcq("M12L4_D6", "Which change usually increases the turning effect of a motor coil?", ["stronger magnetic field", "weaker magnetic field", "removing the current", "making the coil parallel to the field forever"], 0, "A stronger field gives larger force and hence more torque.", ["motor_effect_vs_induction_confusion"], skill_tags=["motor_strength"]),
        mcq("M12L4_D7", "Which other change also usually increases the turning effect?", ["larger current or more turns in the coil", "smaller current and fewer turns", "zero current", "removing one side of the loop"], 0, "More current or turns strengthens the motor effect.", ["motor_effect_vs_induction_confusion"], skill_tags=["motor_strength"]),
        short("M12L4_D8", "Why is the commutator needed for continuous turning in a simple d.c. motor?", ["Because without reversing the current each half-turn, the turning effect would reverse and the coil would not keep spinning in one direction.", "Because the split ring flips the current at the right time so the torque continues in the same overall direction."], "Tie continuous turning to current reversal timing.", ["commutator_role_confusion"], skill_tags=["commutator_role"], acceptance_rules=acceptance_groups(["reverse", "flip"], ["current"], ["half-turn", "right time"], ["keep spinning", "continuous turning", "same direction"], ["commutator", "split ring"])),
        mcq("M12L4_D9", "A d.c. motor mainly converts...", ["electrical energy into kinetic energy", "kinetic energy into electrical energy", "heat into voltage only", "magnetism into sound directly"], 0, "The motor uses electrical input to create motion.", ["motor_effect_vs_induction_confusion"], skill_tags=["energy_conversion"]),
        mcq("M12L4_D10", "Best first question in a motor-effect diagram:", ["Which sides of the coil get opposite side-kicks?", "How many field lines are decorative?", "What is the transmission voltage?", "What is the transformer core made of?"], 0, "Motor reasoning starts by locating the opposing forces on the coil sides.", ["motor_effect_vs_induction_confusion"], skill_tags=["prediction_habit"]),
    ]
    c = [
        short("M12L4_C1", "How is a motor just Lesson 3 arranged to produce rotation?", ["A motor places current-carrying sides of a coil in a magnetic field so opposite magnetic forces create torque instead of just one sideways push.", "It uses the same force-on-conductor idea on opposite sides of a loop to make a turning effect."], "Link the motor directly to the side-kick lesson.", ["motor_effect_vs_induction_confusion"], skill_tags=["motor_effect"], acceptance_rules=acceptance_groups(["same", "force-on-conductor", "side-kick"], ["opposite sides", "coil", "loop"], ["torque", "turning effect", "rotation"])),
        mcq("M12L4_C2", "What happens if the current direction in the coil side is reversed?", ["the force on that side reverses", "the field disappears permanently", "the transformer ratio doubles", "the battery becomes an electromagnet"], 0, "Each coil side still follows the force-direction rule from Lesson 3.", ["force_direction_reversal_confusion"], skill_tags=["coil_side_force"]),
        mcq("M12L4_C3", "Which set of changes should make a motor turn more strongly?", ["more current, more turns, stronger field", "less current, fewer turns, weaker field", "remove the field and keep the coil", "remove the current and keep the field"], 0, "Those factors all strengthen the motor effect.", ["motor_effect_vs_induction_confusion"], skill_tags=["motor_strength"]),
        short("M12L4_C4", "Why is 'the commutator makes the magnet stronger' a weak statement?", ["Because the commutator's job is to reverse the coil current at the right time, not to strengthen the magnetic field directly.", "Because the split ring controls current direction for continuous turning rather than acting as the field source."], "Separate commutator job from field-strength job.", ["commutator_role_confusion"], skill_tags=["commutator_role"], acceptance_rules=acceptance_groups(["commutator", "split ring"], ["reverse", "flip"], ["current"], ["right time", "half-turn", "continuous turning"], ["not", "rather than"], ["strengthen", "field"])),
        mcq("M12L4_C5", "What is the strongest way to explain the energy story in a d.c. motor?", ["Electrical input drives a magnetic turning effect that produces motion.", "The motor creates electricity from motion like a generator.", "The motor stores voltage in the coil forever.", "The motor removes the need for a field."], 0, "Keep the electrical-to-motion conversion clear.", ["motor_effect_vs_induction_confusion"], skill_tags=["energy_conversion"]),
        short("M12L4_C6", "Why might a simple coil need help to keep rotating through awkward positions?", ["Because the turning effect can vary with the coil angle, so a commutator and continued motion help it keep rotating in one direction.", "Because the torque is not equally strong at every angle, so the motor needs the current to be reversed at the right point."], "Add angle-sensitive torque language.", ["commutator_role_confusion"], skill_tags=["motor_continuity"], acceptance_rules=acceptance_groups(["torque", "turning effect"], ["angle"], ["commutator", "reverse current", "right point"], ["keep rotating", "continuous turning"])),
        mcq("M12L4_C7", "Which statement is strongest?", ["A d.c. motor keeps turning because the coil sides repeatedly experience magnetic forces that are managed by the commutator.", "A d.c. motor is just a transformer with a moving wire.", "A d.c. motor works without magnetic forces.", "A d.c. motor relies only on resistance."], 0, "That keeps force and commutator roles together.", ["motor_effect_vs_induction_confusion", "commutator_role_confusion"], skill_tags=["motor_effect"]),
        short("M12L4_C8", "Why is the word 'torque' useful in Lesson 4?", ["Because it names the turning effect produced when opposite forces act on opposite sides of the coil.", "Because it distinguishes rotation from a simple sideways shift."], "Use torque to keep turning distinct from translation.", ["motor_effect_vs_induction_confusion"], skill_tags=["torque_cause"], acceptance_rules=acceptance_groups(["torque", "turning effect"], ["opposite forces", "opposite sides"], ["coil"], ["rotation", "turning"], ["not", "rather than"], ["simple sideways shift", "translation"])),
    ]
    t = [
        mcq("M12L4_M1", "A coil in a magnetic field is carrying current. What is the strongest reason it can turn?", ["The two active sides of the coil experience opposite magnetic forces that create torque.", "The field lines pull the whole loop forward equally.", "The coil stores current in the core.", "The generator has already induced a voltage."], 0, "Turning comes from opposite forces on opposite sides.", ["motor_effect_vs_induction_confusion"], skill_tags=["torque_cause"]),
        short("M12L4_M2", "How would you correct the statement 'a motor is just induction'?", ["I would say a motor mainly uses the magnetic force on a current-carrying coil to create torque, while induction is the story of emf from changing magnetic flux.", "I would separate the motor effect from induction: motors use force on current, while generators and transformers rely on changing flux."], "Separate force and induction cleanly.", ["motor_effect_vs_induction_confusion"], skill_tags=["motor_effect"], acceptance_rules=acceptance_groups(["motor"], ["force", "current-carrying coil", "torque"], ["induction", "changing flux", "emf"], ["separate", "rather than"])),
        mcq("M12L4_M3", "If the magnetic field is made stronger while the coil current stays the same, the turning effect should...", ["increase", "decrease", "vanish", "become a transformer ratio"], 0, "Stronger field means stronger coil-side forces.", ["motor_effect_vs_induction_confusion"], skill_tags=["motor_strength"]),
        short("M12L4_M4", "Why does a split-ring commutator help a d.c. motor keep spinning in one direction?", ["Because it reverses the current each half-turn so the torque keeps pushing the same overall way.", "Because it switches the coil connections at the right time to sustain rotation."], "Use half-turn reversal language.", ["commutator_role_confusion"], skill_tags=["commutator_role"], acceptance_rules=acceptance_groups(["reverse", "switch"], ["current"], ["half-turn", "right time"], ["torque", "keep spinning", "same direction"])),
        mcq("M12L4_M5", "Which combination should give the greatest turning effect?", ["many turns, large current, strong field", "few turns, small current, weak field", "no field and no current", "fewer turns with current switched off"], 0, "Those are the standard strengthening factors.", ["motor_effect_vs_induction_confusion"], skill_tags=["motor_strength"]),
        short("M12L4_M6", "Why do opposite forces on opposite sides of a loop not simply cancel into no effect?", ["Because they act at different positions and form a turning couple, so they create torque on the loop.", "Because the forces are separated around the loop and therefore produce rotation instead of just cancellation."], "Use couple-or-torque language.", ["motor_effect_vs_induction_confusion"], skill_tags=["torque_cause"], acceptance_rules=acceptance_groups(["different positions", "opposite sides"], ["couple", "torque", "turning moment"], ["loop", "coil"], ["not", "rather than"], ["cancel"])),
        mcq("M12L4_M7", "What is the main output of a working d.c. motor?", ["mechanical rotation", "transformer voltage ratio", "field-line density only", "static induced current without motion"], 0, "The motor's job is rotation.", ["motor_effect_vs_induction_confusion"], skill_tags=["energy_conversion"]),
        short("M12L4_M8", "How does Lesson 4 deepen the side-kick idea from Lesson 3?", ["It puts the side-kick on opposite sides of a coil so the result is torque and continuous rotation rather than one sideways push.", "It turns the force-on-conductor story into a machine that spins."], "Show the jump from force to machine.", ["motor_effect_vs_induction_confusion"], skill_tags=["motor_effect"], acceptance_rules=acceptance_groups(["side-kick", "force-on-conductor"], ["opposite sides", "coil"], ["torque", "rotation", "spins"], ["rather than", "instead of"], ["one sideways push"])),
        mcq("M12L4_M9", "Which statement is weakest?", ["The commutator is mainly there to make the magnet stronger.", "A d.c. motor turns because its coil sides feel magnetic forces.", "Current direction matters for the motor effect.", "The motor effect is a turning use of magnetic force."], 0, "The commutator is not the field-strength control.", ["commutator_role_confusion"], skill_tags=["commutator_role"]),
        short("M12L4_M10", "Why is a motor a natural part of the Field-Weave model rather than a random machine chapter?", ["Because it is just the magnetic side-kick idea organized into a rotating coil, so the machine follows directly from the field-force rules.", "Because the motor uses the field to push current-carrying coil sides and create torque."], "Keep the machine grounded in the field rules.", ["motor_effect_vs_induction_confusion"], skill_tags=["motor_effect"], acceptance_rules=acceptance_groups(["field", "magnetic side-kick", "force"], ["coil", "current-carrying"], ["torque", "rotation"], ["follows directly", "natural part", "same model"])),
    ]
    return lesson_spec(
        "M12_L4",
        "Spin Frames and the Motor Effect",
        sim(
            "m12_spin_frame_lab",
            "Spin Frame lab",
            "Turn a current-carrying coil in a magnetic field and compare how field strength, current, and turn count change the torque.",
            ["Start with one coil in a field.", "Increase the field or current and compare the torque.", "Switch the commutator on and off to compare the turning behavior."],
            ["Explain the motor effect as torque on a coil.", "Explain the commutator's role in sustained rotation.", "Predict how field strength, current, and turns affect the turning effect."],
            ["field_strength", "coil_current", "turn_count", "torque_readout"],
            "Motor-effect and torque reasoning.",
        ),
        d,
        "A single side-kick can shove one route sideways, but a Spin Frame arranges two current-carrying sides in a field so opposite side-kicks create torque and make the coil turn.",
        "When a motor diagram looks messy, find the two active coil sides and ask how their side-kicks combine into a turning effect.",
        [prompt_block("What makes the coil turn?", "Opposite magnetic forces on opposite sides of the loop."), prompt_block("What keeps a d.c. motor turning the same way?", "The split-ring commutator reversing current at the right time.")],
        [prompt_block("Start with a modest field and current and read the torque.", "The loop turns because the two sides feel opposite forces."), prompt_block("Now toggle the commutator support.", "Without the timed current reversal, the turning will not stay in one direction as cleanly.")],
        ["Explain why a motor is a turning version of the side-kick story.", "Explain why the commutator matters in a simple d.c. motor."],
        "Torque is the key new quantity here. Keep it separate from translation so the motor does not get described as just another sideways force example.",
        c,
        t,
        contract(
            concept_targets=[
                "Explain the motor effect as torque on a current-carrying coil in a magnetic field.",
                "Explain why opposite magnetic forces on opposite sides of the coil create rotation.",
                "Explain the role of the split-ring commutator in a simple d.c. motor.",
            ],
            core_concepts=[
                "A current-carrying loop in a magnetic field experiences forces on its sides.",
                "Opposite forces on opposite sides can produce torque.",
                "The motor effect is a turning use of the magnetic force on current-carrying conductors.",
                "The split-ring commutator reverses current each half-turn to sustain overall rotation.",
                "Stronger field, larger current, and more turns increase the motor effect.",
            ],
            prerequisite_lessons=["M12_L3"],
            misconception_focus=[
                "motor_effect_vs_induction_confusion",
                "commutator_role_confusion",
                "force_direction_reversal_confusion",
            ],
            formulas=[
                relation("field up / current up / turns up -> turning effect up", "Torque increases when the magnetic interaction on the coil becomes stronger.", ["qualitative"], "Use qualitatively for motor-strength questions."),
                relation("commutator flips current each half-turn", "The current reversal keeps the turning effect acting in one overall rotational sense.", ["qualitative"], "Use for simple d.c.-motor direction reasoning."),
            ],
            representations=[
                representation("coil-force diagram", "Shows opposite forces on opposite sides of the loop."),
                representation("torque sketch", "Shows why the forces produce turning rather than pure translation."),
                representation("commutator diagram", "Shows the timed current reversal needed for sustained rotation."),
                representation("energy-flow description", "Links electrical input to kinetic output."),
            ],
            analogy_map=field_weave_map("the class is turning a current-carrying coil and managing the current reversal that keeps it spinning"),
            worked_examples=[
                worked("Why does a current-carrying loop in a field turn instead of just sliding sideways?", ["Identify the two active sides of the loop.", "Note the opposite force directions.", "State the turning result."], "The opposite forces act on opposite sides and create torque on the loop.", "Separated forces can form a couple and produce rotation.", "This turns the side-kick rule into motor reasoning."),
                worked("What does the split-ring commutator actually do?", ["Keep the field in place.", "Reverse the current at the right half-turn.", "State the turning consequence."], "It reverses the coil current each half-turn so the torque keeps pushing the same overall rotational way.", "The commutator manages current direction rather than acting as a field-strength device.", "This blocks one of the most common motor misconceptions."),
                worked("How can you make the turning effect larger without changing the basic machine type?", ["Increase the field strength.", "Increase the coil current.", "Increase the turn count."], "Use a stronger field, larger current, or more turns.", "All three increase the magnetic interaction on the coil.", "This keeps design reasoning connected to the underlying force story."),
                worked("Why is a motor not just a generator running backward in this lesson?", ["Name the motor input and output.", "Name the generator input and output.", "Keep the physical mechanism focus clear."], "A motor uses electrical input to produce motion through magnetic force on a current-carrying coil, while a generator uses changing flux to induce electrical output from motion.", "The machine types are related but not identical in mechanism focus.", "This prepares students for Lesson 5 without merging the two ideas."),
            ],
            visual_assets=[visual("m12-l4-spin-frame", "motor_effect", "Spin frame", "Shows opposite coil-side forces, torque, and commutator timing in a d.c.-motor picture.", "Keep the opposite side-kicks and the commutator job distinct from the field source.")],
            animation_assets=[animation("m12-l4-spin-cycle", "motor_effect", "Spin cycle", "Shows the coil rotating and the current reversing each half-turn through the commutator.")],
            simulation_contract=sim_contract(
                "m12-l4-spin-frame-lab",
                "motor_effect",
                "How do opposite side-kicks on a current-carrying coil create torque, and how does the commutator sustain the turning?",
                "Start with a coil at a clear angle in a steady magnetic field and a modest current.",
                ["Increase field strength, coil current, or turn count and compare the torque.", "Turn the commutator support off and on to compare how the rotation behaves."],
                "Do not treat the commutator as if it were the source of the field strength.",
                "A d.c. motor is the side-kick force arranged into torque on a coil, with a commutator keeping the turning in one overall direction.",
                [("field_strength", "Field strength", "Sets how strong each coil-side force can be."), ("coil_current", "Coil current", "Changes the force on the coil sides."), ("turn_count", "Turn count", "Shows why more active turns can give more torque.")],
                [("Torque", "Shows the turning effect on the coil."), ("Spin direction", "Shows the overall rotation sense."), ("Commutator state", "Keeps the current-reversal role visible.")],
            ),
            reflection_prompts=[
                "Why is torque the key idea that turns Lesson 3 into Lesson 4?",
                "Why is it scientifically safer to explain the commutator as a current-reversal device than as a field-strength device?",
            ],
            mastery_skills=["motor_definition", "torque_cause", "motor_effect", "commutator_role", "energy_conversion"],
            variation_plan={
                "diagnostic": "Fresh attempts rotate between torque meaning, commutator role, and strengthening-factor stems.",
                "concept_gate": "Concept checks vary between force-to-torque reasoning, motor-versus-induction distinctions, and continuity of turning.",
                "mastery": "Mastery mixes torque reasoning, commutator corrections, and motor-strength comparisons before repeating any prompt.",
            },
            scaffold_support=scaffold(
                "A motor is the magnetic side-kick story arranged into torque on a coil.",
                "Find the two active sides, track their force directions, then ask how the commutator keeps the turning consistent.",
                "If opposite forces act on opposite sides of the loop, what new effect should you expect besides simple sideways motion?",
                "Do not let the word commutator become a vague label that hides the actual current-reversal job.",
                "The spin frame is a loop set inside a field weave so each side gets a side-kick in opposite directions, and those separated kicks twist the frame around.",
                "What changes each half-turn so the frame can keep rotating in one direction?",
                [
                    extra_section("Torque not translation", "The important output here is turning. The motor is not just sliding sideways because the two main forces act on different sides of the loop.", "Why do the two forces create rotation instead of just one sideways drift?"),
                    extra_section("Timed current reversal", "A simple d.c. motor needs the current reversed at the right point so the torque continues in the same overall sense.", "Why does the motor care about the timing of the current reversal?"),
                ],
            ),
            visual_clarity_checks=visual_checks("motor-effect"),
        ),
    )


def induction_lesson() -> Dict[str, Any]:
    d = [
        mcq("M12L5_D1", "Induction in this module means creating...", ["an emf by changing magnetic flux through a conductor or coil", "a stronger permanent magnet without current", "a field map without any change", "a transformer core from plastic"], 0, "Induction is about emf from changing magnetic flux.", ["induction_static_field_confusion"], skill_tags=["induction_definition"]),
        mcq("M12L5_D2", "A steady magnet held motionless near a coil usually gives...", ["no sustained induced emf", "the largest possible induced emf", "a step-up transformer automatically", "a stronger battery voltage forever"], 0, "Static field alone does not keep inducing emf.", ["induction_static_field_confusion"], skill_tags=["need_change"]),
        mcq("M12L5_D3", "Moving a magnet into a coil can induce an emf because...", ["the magnetic flux through the coil is changing", "the coil resistance has vanished", "the battery inside the magnet turned on", "field lines themselves carry charge into the coil"], 0, "The key word is change in flux.", ["induction_static_field_confusion"], skill_tags=["flux_change"]),
        mcq("M12L5_D4", "If the magnet is moved faster, the induced emf is usually...", ["larger", "smaller", "unchanged forever", "zero"], 0, "Faster change means stronger induction.", ["induction_static_field_confusion"], skill_tags=["induction_strength"]),
        mcq("M12L5_D5", "If the coil has more turns while the same flux change happens, the induced emf is usually...", ["larger", "smaller", "unchanged forever", "replaced by current only"], 0, "More turns means more induced effect at this level.", ["induction_static_field_confusion"], skill_tags=["turns_effect"]),
        short("M12L5_D6", "Why is 'a field induces current just by existing' a weak statement?", ["Because induction needs changing magnetic flux, not merely the presence of a steady field.", "Because a static field alone does not keep producing an induced emf in the coil."], "Keep the change requirement explicit.", ["induction_static_field_confusion"], skill_tags=["need_change"], acceptance_rules=acceptance_groups(["induction"], ["change", "changing"], ["magnetic flux", "field through the coil"], ["not", "rather than"], ["steady field", "static field", "just existing"])),
        mcq("M12L5_D7", "Lenz's law says the induced effect acts to...", ["oppose the change that caused it", "speed the change up as much as possible", "remove the magnetic field from the universe", "make all outputs d.c."], 0, "The induced effect opposes the change.", ["lenz_law_confusion"], skill_tags=["lenz_law"]),
        mcq("M12L5_D8", "A generator works by...", ["repeatedly changing magnetic flux through a coil", "keeping a field perfectly static", "using a split-ring commutator to sustain motor torque", "making a bar magnet without current"], 0, "A generator is repeated induction.", ["generator_current_type_confusion", "motor_effect_vs_induction_confusion"], skill_tags=["generator_principle"]),
        short("M12L5_D9", "Why does an a.c. generator produce alternating emf?", ["Because the rotating coil keeps changing its orientation in the field, so the induced emf reverses direction repeatedly.", "Because continuous rotation makes the flux change reverse in a repeating cycle."], "Use repeated reversal language.", ["generator_current_type_confusion"], skill_tags=["ac_generator"], acceptance_rules=acceptance_groups(["rotating coil", "orientation"], ["field", "flux"], ["reverses", "alternates", "repeatedly"], ["emf", "output"])),
        mcq("M12L5_D10", "Best first question in an induction problem:", ["What is changing, and how fast is it changing?", "What color is the magnet?", "How many lamps are in series?", "Which way does the compass point at rest?"], 0, "Start by identifying the changing flux story.", ["induction_static_field_confusion"], skill_tags=["prediction_habit"]),
    ]
    c = [
        short("M12L5_C1", "What does the Change-Thread idea stand for in formal physics?", ["It stands for changing magnetic flux through a loop or conductor.", "It means that the amount of magnetic field threading the loop is changing."], "Flux change is the core formal idea.", ["induction_static_field_confusion"], skill_tags=["flux_change"], acceptance_rules=acceptance_groups(["change-thread", "changing"], ["magnetic flux", "field through the loop"], ["coil", "loop", "conductor"])),
        mcq("M12L5_C2", "A magnet is held still inside a coil after being pushed in. The induced emf then is best described as...", ["no sustained induced emf", "largest possible", "always step-down", "equal to the battery voltage"], 0, "The change has stopped, so sustained induction stops.", ["induction_static_field_confusion"], skill_tags=["need_change"]),
        mcq("M12L5_C3", "Which setup should produce the largest induced emf?", ["fastest flux change with the greatest turn count", "static magnet and single turn", "no field change and zero turns", "slowest motion and fewest turns"], 0, "Largest change and more turns give the largest induced effect.", ["induction_static_field_confusion"], skill_tags=["induction_strength"]),
        short("M12L5_C4", "Why does reversing the magnet motion reverse the induced emf direction?", ["Because the magnetic flux change reverses, so the induced effect reverses too.", "Because the coil is now experiencing the opposite change-thread."], "Tie direction to the sign of the change.", ["lenz_law_confusion"], skill_tags=["reverse_change"], acceptance_rules=acceptance_groups(["reversing", "opposite"], ["magnet motion", "motion"], ["magnetic flux change", "change-thread", "flux"], ["induced emf", "induced effect"], ["reverses", "opposite direction"])),
        mcq("M12L5_C5", "Which statement is strongest?", ["A generator is repeated induction produced by continuous flux change.", "A generator is just a motor with no field.", "A generator works best when the field is perfectly static.", "A generator does not involve magnetic flux."], 0, "Keep the generator inside the induction story.", ["generator_current_type_confusion", "motor_effect_vs_induction_confusion"], skill_tags=["generator_principle"]),
        short("M12L5_C6", "How does Lenz's law help you describe induction without equations?", ["It says the induced effect acts to oppose the change that caused it.", "It says the induced current or emf resists the changing magnetic situation that produced it."], "Use opposition-to-change language.", ["lenz_law_confusion"], skill_tags=["lenz_law"], acceptance_rules=acceptance_groups(["oppose", "resist"], ["change"], ["induced current", "induced emf", "induced effect"])),
        mcq("M12L5_C7", "Which energy-conversion story fits an a.c. generator?", ["mechanical motion into electrical output", "electrical input into rotation", "static field into resistance", "charge into mass"], 0, "Generators use motion to produce electrical output.", ["generator_current_type_confusion", "motor_effect_vs_induction_confusion"], skill_tags=["generator_energy"]),
        short("M12L5_C8", "Why is a generator not just the motor effect with a different name?", ["Because a generator is about inducing emf from changing magnetic flux, whereas the motor effect is about force and torque on current-carrying conductors.", "Because the generator's central mechanism is induction, not the direct magnetic side-kick on a powered coil."], "Separate force from induction clearly.", ["motor_effect_vs_induction_confusion"], skill_tags=["generator_principle"], acceptance_rules=acceptance_groups(["generator"], ["induction", "changing magnetic flux", "induced emf"], ["motor effect", "force", "torque"], ["not", "rather than"], ["different name", "same thing"])) ,
    ]
    t = [
        mcq("M12L5_M1", "Which change should most strongly increase the induced emf in a coil?", ["move the magnet faster through a many-turn coil", "hold the magnet still", "remove the coil and keep the air", "leave everything unchanged"], 0, "Faster change and more turns strengthen induction.", ["induction_static_field_confusion"], skill_tags=["induction_strength"]),
        short("M12L5_M2", "A learner says the coil should keep producing emf as long as a magnet is nearby. What is the correction?", ["I would say emf is induced only while the magnetic flux through the coil is changing, not just because a magnet is present.", "I would say a steady nearby magnet does not keep inducing emf unless something about the flux is changing."], "Correct the static-field myth.", ["induction_static_field_confusion"], skill_tags=["need_change"], acceptance_rules=acceptance_groups(["emf", "induced"], ["only while", "when"], ["changing"], ["magnetic flux", "field through the coil"], ["not", "rather than"], ["magnet nearby", "steady magnet"])),
        mcq("M12L5_M3", "If a magnet is pushed into a coil and then pulled out, the induced emf direction will...", ["reverse between the two motions", "stay the same forever", "always vanish", "become transformer d.c."], 0, "Opposite flux change gives opposite induced direction.", ["lenz_law_confusion"], skill_tags=["reverse_change"]),
        short("M12L5_M4", "Why does more turn count help induction?", ["Because the changing magnetic flux links more turns, so the induced emf becomes larger.", "Because extra turns strengthen the induced effect for the same change-thread."], "Use linked-turns language.", ["induction_static_field_confusion"], skill_tags=["turns_effect"], acceptance_rules=acceptance_groups(["more turns", "extra turns"], ["changing magnetic flux", "change-thread"], ["larger", "stronger"], ["induced emf", "induced effect"])),
        mcq("M12L5_M5", "Which statement matches Lenz's law best?", ["The induced effect opposes the change that produces it.", "The induced effect always speeds the change up.", "The induced effect ignores change direction.", "Lenz's law only applies to transformers."], 0, "Opposition to change is the key idea.", ["lenz_law_confusion"], skill_tags=["lenz_law"]),
        short("M12L5_M6", "How would you explain an a.c. generator using the Field-Weave model?", ["A turn-wheel keeps changing the magnetic thread through the coil, so the induced emf repeatedly reverses and becomes alternating output.", "The rotating coil or magnet makes the flux change again and again, creating alternating emf."], "Keep the repeated-change idea visible.", ["generator_current_type_confusion"], skill_tags=["ac_generator"], acceptance_rules=acceptance_groups(["rotating", "turn-wheel"], ["changing", "repeatedly"], ["magnetic flux", "magnetic thread"], ["induced emf", "output"], ["alternating", "reverses"])),
        mcq("M12L5_M7", "Which case is not an induction case?", ["a steady magnet held motionless near a coil", "a magnet moving into a coil", "a conductor moving across a field", "a changing current in a nearby coil"], 0, "Induction needs change, not just presence.", ["induction_static_field_confusion"], skill_tags=["need_change"]),
        short("M12L5_M8", "Why is a generator naturally placed after the induction lesson rather than before it?", ["Because a generator is an application of induction: it keeps changing magnetic flux to produce repeated emf.", "Because the machine makes sense only after students understand that changing flux induces emf."], "Application follows principle.", ["generator_current_type_confusion", "motor_effect_vs_induction_confusion"], skill_tags=["generator_principle"], acceptance_rules=acceptance_groups(["generator"], ["application", "uses"], ["induction"], ["changing flux", "changing magnetic flux"], ["emf", "output"])),
        mcq("M12L5_M9", "A generator converts...", ["mechanical motion into electrical output by induction", "electrical input into motion by torque", "static field into heat only", "voltage into resistance"], 0, "This keeps generator and motor energy stories separate.", ["generator_current_type_confusion", "motor_effect_vs_induction_confusion"], skill_tags=["generator_energy"]),
        short("M12L5_M10", "What single question best protects you from many induction mistakes?", ["Ask what is changing in the magnetic flux through the loop, and how fast that change is happening.", "Ask what the change-thread is, because steady fields alone do not keep inducing emf."], "Start from the change.", ["induction_static_field_confusion"], skill_tags=["prediction_habit"], acceptance_rules=acceptance_groups(["what is changing", "change-thread"], ["magnetic flux", "field through the loop"], ["how fast", "rate of change"], ["steady fields", "not static alone"])),
    ]
    return lesson_spec(
        "M12_L5",
        "Change-Thread, Induction, and Turn-Wheels",
        sim(
            "m12_change_thread_lab",
            "Change-Thread lab",
            "Induce emf by changing magnetic flux through a coil, then extend the same logic into an a.c. generator.",
            ["Move a magnet into and out of a coil.", "Change the speed and turn count.", "Switch to turn-wheel mode and compare the alternating output."],
            ["Explain why induction requires change.", "Explain how speed and turns affect induced emf.", "Explain why a generator produces alternating output."],
            ["flux_change_rate", "turn_count", "induced_emf", "output_mode"],
            "Induction and generator reasoning.",
        ),
        d,
        "A field can push a current-carrying route sideways, but a changing field-thread can do something deeper: it can create a brand-new loop push in another conductor.",
        "Do not ask merely whether a field is present. Ask what is changing about the magnetic thread through the loop.",
        [prompt_block("What is needed for induction?", "Changing magnetic flux through the loop."), prompt_block("What machine turns repeated flux change into electrical output?", "An a.c. generator.")],
        [prompt_block("Move the magnet slowly into the coil and note the induced emf.", "There is induction only while the flux is changing."), prompt_block("Now move it faster and add more turns.", "The induced effect should grow.")],
        ["Explain why a steady nearby magnet is not enough for sustained induction.", "Explain why a generator is an induction machine rather than a motor."],
        "The induction lesson is about change, sign, and rate. Keep those three ideas visible and most generator mistakes get much easier to avoid.",
        c,
        t,
        contract(
            concept_targets=[
                "Explain induction as emf produced by changing magnetic flux.",
                "Explain how speed of change and turn count affect induced emf.",
                "Explain an a.c. generator as repeated induction from continuous flux change.",
            ],
            core_concepts=[
                "A steady field alone does not sustain induction.",
                "Changing magnetic flux through a conductor or coil induces emf.",
                "Faster flux change gives a larger induced effect.",
                "More turns increase the induced effect.",
                "An a.c. generator produces alternating output because the flux change repeatedly reverses.",
            ],
            prerequisite_lessons=["M12_L1", "M12_L4"],
            misconception_focus=[
                "induction_static_field_confusion",
                "lenz_law_confusion",
                "generator_current_type_confusion",
                "motor_effect_vs_induction_confusion",
            ],
            formulas=[
                relation("rate of flux change up -> induced emf up", "Stronger or faster magnetic change produces a larger induced effect.", ["qualitative"], "Use as a proportional reasoning rule rather than a numerical derivation."),
                relation("turn count up -> induced emf up", "More turns linked by the changing flux increase the induced effect.", ["qualitative"], "Use for comparison questions."),
            ],
            representations=[
                representation("motion-through-coil sketch", "Shows that induction depends on changing magnetic flux."),
                representation("sign-change comparison", "Shows why opposite motion gives opposite induced direction."),
                representation("generator cycle diagram", "Shows repeated flux change and alternating output."),
                representation("words", "Keeps induction distinct from motor torque."),
            ],
            analogy_map=field_weave_map("the class is changing magnetic thread through a coil and then turning that change into generator output"),
            worked_examples=[
                worked("A magnet is held motionless near a coil. Should you expect sustained induced emf?", ["Ask what is changing.", "Check the flux through the coil.", "State the conclusion."], "No sustained induced emf is expected because the flux is not changing.", "Induction needs change, not merely presence of a field.", "This is the key shield against the static-field misconception."),
                worked("Why does pushing the magnet faster give a larger induced emf?", ["Compare the slow and fast cases.", "Ask which changes flux more quickly.", "State the consequence."], "The faster motion gives a larger induced emf because the flux changes more quickly.", "At this level, induced effect size tracks rate of change.", "This prepares students for both generator and transformer reasoning."),
                worked("Why does pulling the magnet out reverse the induced emf compared with pushing it in?", ["Compare the sign of the flux change.", "Connect that sign change to induced direction.", "State the conclusion."], "The induced emf reverses because the flux change reverses.", "Direction in induction depends on the direction of change, not just on having a magnet nearby.", "This sets up careful generator reasoning."),
                worked("How does a generator make alternating output?", ["Start with a rotating coil or rotating magnet.", "Notice that the flux through the coil keeps changing sign and size.", "State the electrical result."], "The repeated reversal of flux change makes the induced emf alternate.", "Alternating output follows from repeating the induction cycle in opposite senses.", "This keeps the generator inside the induction story instead of turning it into a separate machine chapter."),
            ],
            visual_assets=[visual("m12-l5-change-thread", "induction", "Change-thread", "Shows a magnet moving through a coil, the induced emf, and a generator cycle built from repeated flux change.", "Keep static-field and changing-field cases visually separate so students can see why only one induces emf.")],
            animation_assets=[animation("m12-l5-generator-cycle", "induction", "Generator cycle", "Shows the induced emf reversing as the turn-wheel keeps changing the magnetic thread through the coil.")],
            simulation_contract=sim_contract(
                "m12-l5-change-thread-lab",
                "induction",
                "How do change-thread, turn count, and repeated rotation decide the induced emf in induction and generation?",
                "Start with one coil and a magnet moving slowly into the coil before switching to generator mode.",
                ["Increase the magnet speed and compare the induced emf.", "Increase the turn count and compare again.", "Switch to turn-wheel mode and compare how alternating output emerges from repeated flux change."],
                "Do not describe induction as something a static field does automatically just by being present.",
                "Induction needs changing magnetic flux, and a generator is repeated induction produced by continuous flux change.",
                [("flux_change_rate", "Flux-change rate", "Shows why speed matters for induction."), ("turn_count", "Turn count", "Shows why more turns increase the induced effect."), ("output_mode", "Mode", "Compares single induction events with repeated generator cycles.")],
                [("Induced emf", "Shows the size and sign of the induced output."), ("Direction cue", "Shows when the induced direction reverses."), ("Generator output", "Shows why repeated induction becomes alternating output.")],
            ),
            reflection_prompts=[
                "Why is the sentence 'induction needs change' more powerful than a longer but vaguer description?",
                "How does the generator become easier to understand once you stop treating it as a separate chapter and see it as repeated induction?",
            ],
            mastery_skills=["induction_definition", "need_change", "flux_change", "lenz_law", "ac_generator"],
            variation_plan={
                "diagnostic": "Fresh attempts rotate between change-versus-static cases, generator meaning, and Lenz-law wording.",
                "concept_gate": "Concept checks vary between reversal reasoning, turn-count reasoning, and generator-versus-motor distinctions.",
                "mastery": "Mastery mixes change-rate comparisons, misconception correction, and generator explanations before repeating any prompt.",
            },
            scaffold_support=scaffold(
                "Induction is the story of changing magnetic thread creating a new loop push.",
                "Start every induction question by asking what is changing, what direction the change has, and how quickly it is happening.",
                "If a magnet is simply sitting still nearby, what change is missing from the induction story?",
                "Do not say a field induces current just because it exists.",
                "A loop feels a new push only when the field thread through it changes. Repeating that change by rotation turns the same idea into generator output.",
                "Which word matters most in induction: field, or changing field-thread?",
                [
                    extra_section("Change, not presence", "A nearby magnet is not enough by itself. What matters is whether the magnetic thread through the loop is changing.", "Why does a steady magnet fail to keep inducing emf?"),
                    extra_section("Generator as repeated induction", "A generator keeps changing the magnetic thread again and again, so the induced emf repeats and reverses.", "Why does the output of an a.c. generator alternate?"),
                ],
            ),
            visual_clarity_checks=visual_checks("induction"),
        ),
    )


def transformer_lesson() -> Dict[str, Any]:
    d = [
        mcq("M12L6_D1", "A Twin-Coil Bridge stands for a...", ["transformer", "d.c. motor", "permanent magnet only", "compass probe"], 0, "The twin-coil bridge is the transformer picture.", ["transformer_dc_confusion"], skill_tags=["transformer_definition"]),
        mcq("M12L6_D2", "An ordinary transformer works because the primary coil creates...", ["a changing magnetic field in the core", "a permanent magnet that never changes", "sideways force on a moving wire only", "current directly jumping through the air gap"], 0, "Transformer action depends on a changing field in the shared core.", ["transformer_dc_confusion"], skill_tags=["transformer_principle"]),
        mcq("M12L6_D3", "Why is a.c. normally needed for an ordinary transformer?", ["Because a changing current creates the changing magnetic field needed for induction in the secondary.", "Because d.c. always has higher voltage.", "Because a.c. removes the need for a core.", "Because current must travel through the core metal."], 0, "Ordinary transformers rely on changing magnetic flux in the core.", ["transformer_dc_confusion"], skill_tags=["ac_requirement"]),
        mcq("M12L6_D4", "If the secondary has more turns than the primary, the transformer is mainly...", ["step-up", "step-down", "a motor", "a fuse"], 0, "More secondary turns gives a higher secondary voltage.", ["turns_ratio_confusion"], skill_tags=["step_up_down"]),
        mcq("M12L6_D5", "If the secondary has fewer turns than the primary, the transformer is mainly...", ["step-down", "step-up", "a generator", "an electromagnet with no induction"], 0, "Fewer secondary turns gives a lower secondary voltage.", ["turns_ratio_confusion"], skill_tags=["step_up_down"]),
        short("M12L6_D6", "Why does steady d.c. fail to keep an ordinary transformer working after the instant of switching?", ["Because after the brief switching change there is no continuing changing magnetic flux to induce a sustained secondary emf.", "Because an ordinary transformer needs a continually changing field, and steady d.c. does not provide that."], "Keep the changing-field requirement explicit.", ["transformer_dc_confusion", "induction_static_field_confusion"], skill_tags=["ac_requirement"], acceptance_rules=acceptance_groups(["changing field", "changing magnetic flux"], ["ordinary transformer"], ["steady d.c.", "direct current"], ["not", "fails", "does not provide"], ["sustained", "continuing"], ["secondary emf", "induced output"])),
        mcq("M12L6_D7", "Which relation matches the school transformer ratio best?", ["Vs/Vp = Ns/Np", "Is/Ip = Ns/Np", "P = Ns/Np", "R = V + I"], 0, "Voltage ratio matches turn ratio in this school model.", ["turns_ratio_confusion"], skill_tags=["turns_ratio"]),
        mcq("M12L6_D8", "For a given power, raising the transmission voltage usually makes the line current...", ["smaller", "larger", "unchanged forever", "equal to the resistance"], 0, "P = IV, so higher V means lower I for the same power.", ["transmission_voltage_loss_confusion"], skill_tags=["transmission_reasoning"]),
        short("M12L6_D9", "Why does a smaller transmission current help reduce cable losses?", ["Because cable heating losses depend on current, so a smaller current reduces those losses.", "Because lower current means less I^2R heating in the transmission cables."], "Use lower-current lower-loss language.", ["transmission_voltage_loss_confusion"], skill_tags=["transmission_reasoning"], acceptance_rules=acceptance_groups(["smaller", "lower"], ["current"], ["reduce", "lower"], ["losses", "heating", "I^2R"], ["cables", "transmission"])),
        mcq("M12L6_D10", "Best first question when reading a transformer setup:", ["Which coil is primary, which is secondary, and how do their turns compare?", "Which pole of the compass is nearest?", "How bright is the field line?", "What is the motor torque?"], 0, "Identify the coils and turns before calculating.", ["turns_ratio_confusion"], skill_tags=["prediction_habit"]),
    ]
    c = [
        short("M12L6_C1", "How can the secondary coil receive energy without charge from the primary physically traveling through the core?", ["Because the primary creates a changing magnetic field in the shared core, and that changing field induces emf in the secondary.", "Because the coils are linked by induction through the changing core field rather than by charge flowing directly from one coil into the other."], "Keep induction, not charge transfer, at the center.", ["transformer_dc_confusion"], skill_tags=["transformer_principle"], acceptance_rules=acceptance_groups(["changing magnetic field", "changing core field"], ["induces", "induction"], ["secondary emf", "secondary output"], ["not", "rather than"], ["charge flowing directly", "direct charge transfer"])),
        mcq("M12L6_C2", "A transformer has Np = 200 turns and Ns = 50 turns. If Vp = 240 V, Vs is...", ["60 V", "960 V", "240 V", "120 V"], 0, "Use Vs/Vp = Ns/Np = 50/200.", ["turns_ratio_confusion"], skill_tags=["turns_ratio_calc"]),
        mcq("M12L6_C3", "A transformer has Np = 100 turns and Ns = 400 turns. If Vp = 12 V, Vs is...", ["48 V", "3 V", "12 V", "400 V"], 0, "Step-up by a factor of 4.", ["turns_ratio_confusion"], skill_tags=["turns_ratio_calc"]),
        short("M12L6_C4", "Why is 'the current just travels through the core into the second coil' a weak explanation?", ["Because the coils are linked by changing magnetic flux in the core, not by charges moving from the primary wire into the secondary wire.", "Because transformer action is induction between two coils, not direct charge transfer through the core."], "Keep the core as field link, not a current tunnel.", ["transformer_dc_confusion"], skill_tags=["transformer_principle"], acceptance_rules=acceptance_groups(["changing magnetic flux", "changing field", "induction"], ["core"], ["secondary", "second coil"], ["not", "rather than"], ["charge transfer", "current travels through the core", "current tunnel"])),
        mcq("M12L6_C5", "Why is high-voltage transmission useful for the same power?", ["It reduces current and therefore reduces I^2R cable losses.", "It increases cable losses because voltage is larger.", "It removes the need for transformers.", "It turns a.c. into d.c. automatically."], 0, "Higher V allows lower I for the same power.", ["transmission_voltage_loss_confusion"], skill_tags=["transmission_reasoning"]),
        short("M12L6_C6", "Why is a step-up transformer usually followed later by step-down transformers before homes and devices?", ["Because the voltage is raised for efficient transmission and then lowered again for practical use and safety at the user end.", "Because the grid uses high voltage to cut transmission losses, but homes need the voltage reduced again before use."], "Keep transmission efficiency and user delivery separate.", ["transmission_voltage_loss_confusion"], skill_tags=["grid_delivery"], acceptance_rules=acceptance_groups(["raise", "high voltage", "step-up"], ["transmission", "efficient", "lower current"], ["lower again", "step-down"], ["homes", "devices", "user end", "practical use"])),
        mcq("M12L6_C7", "Which statement is strongest?", ["A transformer is an induction device that links two coils with a shared changing magnetic field.", "A transformer is just a motor with fixed torque.", "A transformer works best with steady d.c.", "A transformer ignores turn count."], 0, "That keeps induction, two coils, and changing field together.", ["transformer_dc_confusion", "turns_ratio_confusion"], skill_tags=["transformer_definition"]),
        short("M12L6_C8", "How does Lesson 6 extend the induction story from Lesson 5?", ["It uses changing magnetic flux from one coil to induce emf in another coil, and then uses turn count to control the output voltage.", "It turns induction into a two-coil bridge where AC in the primary produces induced output in the secondary."], "Induction now links two coils instead of one moving magnet and one coil.", ["transformer_dc_confusion", "turns_ratio_confusion"], skill_tags=["transformer_principle"], acceptance_rules=acceptance_groups(["changing magnetic flux", "induction"], ["one coil", "primary"], ["another coil", "secondary"], ["turn count", "turns ratio", "control output voltage"])),
    ]
    t = [
        mcq("M12L6_M1", "A transformer has Np = 500 turns, Ns = 100 turns, and Vp = 240 V. Vs is...", ["48 V", "1200 V", "240 V", "24 V"], 0, "Step-down by a factor of 5.", ["turns_ratio_confusion"], skill_tags=["turns_ratio_calc"]),
        mcq("M12L6_M2", "A transformer has Np = 50 turns, Ns = 200 turns, and Vp = 12 V. Vs is...", ["48 V", "3 V", "12 V", "200 V"], 0, "Step-up by a factor of 4.", ["turns_ratio_confusion"], skill_tags=["turns_ratio_calc"]),
        short("M12L6_M3", "A learner says the secondary coil gets energy because primary charges flow through the core into it. What should you say instead?", ["I would say the primary creates a changing magnetic field in the core, and that changing field induces emf in the secondary without direct charge transfer between coils.", "I would say the transformer link is induction through the shared changing field, not charge flowing from one coil into the other."], "Correct the direct-transfer picture.", ["transformer_dc_confusion"], skill_tags=["transformer_principle"], acceptance_rules=acceptance_groups(["changing magnetic field", "changing flux", "induction"], ["core"], ["secondary"], ["not", "rather than"], ["direct charge transfer", "charges flow through the core", "current through the core"])),
        mcq("M12L6_M4", "For the same transmitted power, raising the line voltage makes the line current...", ["smaller", "larger", "unchanged forever", "equal to the line resistance"], 0, "P = IV keeps the product fixed.", ["transmission_voltage_loss_confusion"], skill_tags=["transmission_reasoning"]),
        short("M12L6_M5", "Why does smaller transmission current reduce cable heating?", ["Because cable losses depend on current, so smaller current means less I^2R heating in the lines.", "Because once the current is reduced, the wires waste less power as heating."], "Keep current-loss reasoning visible.", ["transmission_voltage_loss_confusion"], skill_tags=["transmission_reasoning"], acceptance_rules=acceptance_groups(["smaller", "lower"], ["current"], ["less", "reduce"], ["I^2R", "heating", "losses"], ["cables", "lines"])),
        mcq("M12L6_M6", "Which supply is needed for an ordinary transformer to keep working normally?", ["a.c.", "steady d.c.", "no current at all", "a permanent magnet only"], 0, "Ordinary transformers rely on changing current and changing flux.", ["transformer_dc_confusion"], skill_tags=["ac_requirement"]),
        short("M12L6_M7", "Why is a transformer a natural follow-up to the induction lesson?", ["Because it uses the same induction idea, but now the changing magnetic flux from one coil induces emf in another coil.", "Because transformer action is induction shared between a primary coil and a secondary coil."], "One-coil induction becomes two-coil induction.", ["transformer_dc_confusion"], skill_tags=["transformer_principle"], acceptance_rules=acceptance_groups(["induction"], ["changing magnetic flux", "changing field"], ["one coil", "primary"], ["another coil", "secondary"])),
        mcq("M12L6_M8", "Which transformer choice is best for long-distance transmission if you want lower current for the same power?", ["step-up transformer before the long cables", "step-down transformer before the long cables", "no transformer at all", "steady d.c. source into the core"], 0, "Step voltage up first to reduce current.", ["transmission_voltage_loss_confusion", "turns_ratio_confusion"], skill_tags=["grid_delivery"]),
        short("M12L6_M9", "Why is it unsafe to stop the story at 'just use high voltage everywhere'?", ["Because the grid steps voltage up for efficient transmission and then steps it down again before practical use, so efficiency and user-end delivery are separate parts of the system.", "Because high transmission voltage solves line-loss problems, but homes and devices still need the voltage reduced before use."], "Separate transmission efficiency from final delivery.", ["transmission_voltage_loss_confusion"], skill_tags=["grid_delivery"], acceptance_rules=acceptance_groups(["step up", "high voltage"], ["transmission", "efficient", "lower current"], ["step down", "reduce again"], ["homes", "devices", "user end", "before use"])),
        mcq("M12L6_M10", "Best summary of Lesson 6:", ["A transformer uses changing magnetic flux to link two coils, and turns ratio controls whether the voltage is stepped up or down.", "A transformer is a battery that stores current in a core.", "A transformer only works because charges jump directly from one coil to another.", "A transformer is the same as a motor effect on one wire."], 0, "This summary keeps induction, two coils, and turns ratio together.", ["transformer_dc_confusion", "turns_ratio_confusion"], skill_tags=["lesson_summary"]),
    ]
    return lesson_spec(
        "M12_L6",
        "Twin-Coil Bridges, Transformers, and Grid Transfer",
        sim(
            "m12_grid_bridge_lab",
            "Grid Bridge lab",
            "Link two coils by a changing core field, compare step-up and step-down cases, and connect the transformer story to transmission losses.",
            ["Start with an AC primary and a shared core.", "Change the turns ratio and compare the secondary voltage.", "Switch to transmission mode and compare line current and cable loss clues."],
            ["Explain why transformers need changing current.", "Use the turns ratio to calculate output voltage.", "Explain why high-voltage transmission lowers cable losses for the same power."],
            ["primary_turns", "secondary_turns", "primary_voltage", "line_current"],
            "Transformer and transmission reasoning.",
        ),
        d,
        "A changing field-thread in one loop can create a new push in another loop. The Twin-Coil Bridge turns that induction link into a controllable voltage-changing machine for the grid.",
        "A transformer question is never just a ratio exercise. First identify the changing-field story, then the coil turns, and only then move to the numbers.",
        [prompt_block("What kind of current is needed in an ordinary transformer?", "Changing current, usually AC."), prompt_block("What compares directly with the voltage ratio?", "The turns ratio.")],
        [prompt_block("Start with equal turns on both coils and note the secondary voltage.", "Equal turns give about equal voltage in this simple model."), prompt_block("Now raise the secondary turns and compare the output and line-current story.", "You should see step-up behavior and lower current for the same transmission power.")],
        ["Explain why ordinary transformers need changing current.", "Explain why step-up transmission and later step-down delivery are both part of one coherent grid story."],
        "This lesson is the most integrated one in the module: induction, ratio reasoning, and power-transmission logic all have to stay distinct but connected.",
        c,
        t,
        contract(
            concept_targets=[
                "Explain transformer action as induction between two coils linked by a shared changing magnetic field.",
                "Use the transformer turns ratio to calculate output voltage.",
                "Explain why high-voltage transmission lowers current and reduces cable losses for a given power.",
            ],
            core_concepts=[
                "An ordinary transformer needs a changing current to create a changing magnetic field in the core.",
                "The primary and secondary are linked by induction rather than by direct charge transfer.",
                "Voltage ratio follows turns ratio in the school transformer model.",
                "More secondary turns than primary turns gives step-up behavior, while fewer gives step-down behavior.",
                "For a given power, raising the transmission voltage lowers the line current and reduces I^2R losses.",
            ],
            prerequisite_lessons=["M12_L5", "M10_L6"],
            misconception_focus=[
                "transformer_dc_confusion",
                "turns_ratio_confusion",
                "transmission_voltage_loss_confusion",
                "induction_static_field_confusion",
            ],
            formulas=[
                relation("Vs/Vp = Ns/Np", "Transformer voltage ratio follows turns ratio in the simple model.", ["V", "turns"], "Use for school-level step-up and step-down calculations."),
                relation("P = IV", "For the same power, larger voltage means smaller current.", ["W", "V", "A"], "Use to reason about transmission current."),
                relation("I^2R losses fall when line current falls", "Lower line current reduces cable heating losses.", ["qualitative"], "Use conceptually for transmission questions."),
            ],
            representations=[
                representation("two-coil core diagram", "Shows how the primary and secondary are linked by changing flux in the shared core."),
                representation("turns-ratio equation", "Supports step-up and step-down calculations."),
                representation("grid-delivery flow", "Shows step-up transmission followed by step-down delivery."),
                representation("words", "Keeps direct-charge-transfer misconceptions out of the core story."),
            ],
            analogy_map=field_weave_map("the class is linking two coils by a shared changing field and using turns ratio to manage voltage for the grid"),
            worked_examples=[
                worked("A transformer has Np = 200, Ns = 50, and Vp = 240 V. Find Vs.", ["Use the voltage-turns ratio.", "Write 50/200 as the turns factor.", "Apply it to the primary voltage."], "Vs = 60 V", "The secondary has one quarter as many turns, so it has one quarter of the voltage in this simple model.", "This keeps turns ratio tied directly to voltage ratio."),
                worked("Why does an ordinary transformer need AC rather than steady DC?", ["Ask what induction requires.", "Check what a steady current does to the core field after the switch-on transient.", "State the conclusion."], "It needs AC because only changing current keeps producing changing magnetic flux in the core.", "Ordinary transformer action is sustained induction, not static magnetism.", "This links Lesson 6 directly back to Lesson 5."),
                worked("Why does stepping the voltage up reduce the transmission current for the same power?", ["Use P = IV.", "Hold P fixed.", "State what happens to I when V increases."], "For fixed power, increasing voltage decreases current.", "This is the key reason high-voltage transmission reduces cable losses.", "This connects transformer work to the earlier power ideas without losing the field story."),
                worked("A learner says the current in the primary simply runs through the core into the secondary. What is the better explanation?", ["Keep the two circuits separate.", "State the role of the changing core field.", "State how the secondary gets its emf."], "The primary creates a changing magnetic field in the core, and that changing field induces emf in the secondary without direct charge transfer.", "Transformers are induction links, not current tunnels.", "This is the central misconception shield for the final lesson."),
            ],
            visual_assets=[visual("m12-l6-grid-bridge", "transformer", "Grid bridge", "Shows primary and secondary coils, the shared core field, turns ratio, and step-up/step-down delivery logic.", "Keep the induction link, turns ratio, and transmission story readable as separate layers.")],
            animation_assets=[animation("m12-l6-turns-ratio", "transformer", "Turns ratio", "Shows the changing core field driving a secondary output while the turns ratio changes the voltage level.")],
            simulation_contract=sim_contract(
                "m12-l6-grid-bridge-lab",
                "transformer",
                "How do changing core field, turns ratio, and transmission logic work together in a transformer system?",
                "Start with equal primary and secondary turns and an AC primary supply before comparing step-up and step-down cases.",
                ["Change the turns ratio and calculate the secondary voltage.", "Switch to transmission mode and compare how line current and cable-loss clues change for the same power."],
                "Do not describe transformer action as charges traveling directly from the primary coil through the core into the secondary.",
                "A transformer is a two-coil induction bridge: AC creates a changing core field, turns ratio sets the voltage change, and step-up transmission reduces current and cable loss for the same power.",
                [("primary_turns", "Primary turns", "Sets the input-side turn count for the ratio."), ("secondary_turns", "Secondary turns", "Controls whether the transformer steps voltage up or down."), ("primary_voltage", "Primary voltage", "Gives the input voltage for ratio calculations.")],
                [("Secondary voltage", "Shows the output voltage predicted by the turns ratio."), ("Line current", "Shows why higher transmission voltage can reduce current for the same power."), ("Cable loss clue", "Shows the lower-loss reason for step-up transmission.")],
            ),
            reflection_prompts=[
                "Why does the transformer lesson become much clearer when you keep induction, turns ratio, and transmission logic as separate but linked ideas?",
                "Why is the grid story incomplete unless you mention both step-up transmission and later step-down delivery?",
            ],
            mastery_skills=["transformer_definition", "transformer_principle", "ac_requirement", "turns_ratio", "transmission_reasoning"],
            variation_plan={
                "diagnostic": "Fresh attempts rotate between AC requirement, turns-ratio meaning, and transmission-loss reasoning.",
                "concept_gate": "Concept checks vary between two-coil induction explanations, simple ratio calculations, and grid-delivery explanations.",
                "mastery": "Mastery mixes turns-ratio calculations, misconception correction, and transmission-power reasoning before repeating any prompt.",
            },
            scaffold_support=scaffold(
                "A transformer is induction shared between two coils, and the turns ratio decides how the voltage changes.",
                "Read the field story first, then the turns, and only then the transmission consequences.",
                "If the current in the primary became steady instead of changing, what key ingredient of transformer action would disappear?",
                "Do not imagine charge tunneling directly from the primary into the secondary through the core.",
                "The twin-coil bridge uses one loop to weave a changing field into the core spine and a second loop to catch that changing weave as a new push.",
                "Which two coil properties should you compare before calling a transformer step-up or step-down?",
                [
                    extra_section("Induction across two coils", "The primary does not donate its charges to the secondary. It donates a changing field pattern that induces the secondary emf.", "What travels from primary to secondary in the transformer story: charge, or changing field link?"),
                    extra_section("Grid logic", "High voltage is used for efficient transmission because it lowers current for the same power, and then the voltage is stepped down again before use.", "Why is 'use high voltage everywhere' an incomplete summary?"),
                ],
            ),
            visual_clarity_checks=visual_checks("transformer"),
        ),
    )


M12_SPEC = {
    "authoring_standard": AUTHORING_STANDARD_V3,
    "module_description": "Magnetic fields, electromagnets, force on current-carrying conductors, motor effect, electromagnetic induction, generators, and transformers taught through the Field-Weave model so electricity and magnetism remain one connected system rather than split chapters.",
    "mastery_outcomes": [
        "Describe magnetic fields and read field-line patterns around magnets, wires, and solenoids.",
        "Explain electromagnets as current-produced magnetic fields strengthened by turns and soft-iron cores.",
        "Explain the magnetic force on a current-carrying conductor and predict how the direction changes when current or field reverses.",
        "Explain the motor effect as torque on a current-carrying coil and describe the role of the split-ring commutator in a simple d.c. motor.",
        "Explain induction as emf produced by changing magnetic flux and compare how speed of change and turn count affect the induced effect.",
        "Explain a.c. generators and transformers as applications of induction rather than separate disconnected machines.",
        "Use turns ratio and transmission reasoning to explain why step-up transmission reduces current and cable losses before step-down delivery to users.",
    ],
    "lessons": [
        field_lines_lesson(),
        electromagnet_lesson(),
        side_kick_lesson(),
        motor_lesson(),
        induction_lesson(),
        transformer_lesson(),
    ],
}


RELEASE_CHECKS = [
    "Every lesson keeps fields, forces, induction, and transformer behavior inside one coherent Field-Weave world linked to the earlier current modules.",
    "Every explorer is backed by a lesson-specific simulation contract instead of generic fallback wording.",
    "Every lesson-owned assessment bank is broad enough to prefer unseen questions before repeated stems, with deeper 10/8/10 coverage in diagnostic, concept-gate, and mastery.",
    "Every conceptual short answer accepts varied scientifically correct wording through authored phrase groups.",
    "Every worked example explains why the answer follows instead of naming only the final label.",
    "Every magnetic-field, induction, and transformer visual keeps direction, strength, and device-role labels readable without clipping.",
]


M12_MODULE_DOC, M12_LESSONS, M12_SIM_LABS = build_nextgen_module_bundle(
    module_id=M12_MODULE_ID,
    module_title=M12_MODULE_TITLE,
    module_spec=M12_SPEC,
    allowlist=M12_ALLOWLIST,
    content_version=M12_CONTENT_VERSION,
    release_checks=RELEASE_CHECKS,
    sequence=16,
    level="Module 12",
    estimated_minutes=330,
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


_sync_assessed_skills(M12_LESSONS)


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed Module M12 into Firestore")
    parser.add_argument("--project", default=None)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--compile-assets", action="store_true")
    parser.add_argument("--asset-root", default="")
    parser.add_argument("--public-base", default="/lesson_assets")
    args = parser.parse_args()

    project = get_project_id(args.project)
    init_firebase(project)
    asset_root = args.asset_root or default_asset_root()
    module_doc = deepcopy(M12_MODULE_DOC)
    lesson_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in M12_LESSONS]
    sim_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in M12_SIM_LABS]

    if args.compile_assets:
        render_module_assets(lesson_pairs, sim_pairs, asset_root=asset_root, public_base=args.public_base)

    print_preview(module_doc, lesson_pairs, sim_pairs)
    db = init_firebase(project)
    plan: List[Tuple[str, str]] = [("modules", M12_MODULE_ID)]
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
