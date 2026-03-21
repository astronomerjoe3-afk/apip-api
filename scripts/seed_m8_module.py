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


M8_MODULE_ID = "M8"
M8_CONTENT_VERSION = "20260321_m8_glow_route_v3"
M8_MODULE_TITLE = "Light"
M8_ALLOWLIST = [
    "angle_from_surface_confusion",
    "normal_reference_confusion",
    "reflection_equal_angle_confusion",
    "mirror_image_surface_confusion",
    "refraction_speed_change_confusion",
    "toward_away_normal_confusion",
    "lens_middle_pull_confusion",
    "lens_ray_rule_confusion",
    "critical_angle_confusion",
    "tir_direction_confusion",
    "ray_diagram_literal_confusion",
    "real_virtual_image_confusion",
]


def safe_tags(tags: Sequence[str]) -> List[str]:
    allowed = set(M8_ALLOWLIST)
    return [str(tag) for tag in tags if str(tag) in allowed]


def mcq(qid: str, prompt: str, choices: Sequence[str], answer_index: int, hint: str, tags: Sequence[str], *, skill_tags: Sequence[str]) -> Dict[str, Any]:
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
    phase_key: str = "analogical_grounding",
    template: str = "auto",
    width: int = 1280,
    height: int = 720,
    meta: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    item = {
        "asset_id": asset_id,
        "concept": concept,
        "phase_key": phase_key,
        "title": title,
        "purpose": purpose,
        "caption": caption,
    }
    if template != "auto":
        item["template"] = template
    if width != 1280:
        item["width"] = width
    if height != 720:
        item["height"] = height
    if meta:
        item["meta"] = deepcopy(meta)
    return item


def wave_visual(
    asset_id: str,
    title: str,
    purpose: str,
    caption: str,
    *,
    wave_type: str,
    subtitle: str,
    width: int = 1280,
    height: int = 720,
    meta: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "wave_type": wave_type,
        "subtitle": subtitle,
    }
    if meta:
        payload.update(deepcopy(meta))
    return visual(
        asset_id,
        "wave_diagram",
        title,
        purpose,
        caption,
        template="wave_diagram",
        width=width,
        height=height,
        meta=payload,
    )


def optics_visual(
    asset_id: str,
    title: str,
    purpose: str,
    caption: str,
    *,
    subtitle: str,
    annotation_mode: str,
    object_distance: float,
    object_height: float = 1.0,
    incident_angle_deg: float = 40.0,
    surface_angle_deg: float | None = None,
    guide_line_angle_deg: float | None = None,
    distance_label: str = "",
    principal_rays: int = 3,
    show_image: bool = True,
) -> Dict[str, Any]:
    meta: Dict[str, Any] = {
        "system_type": "plane_mirror",
        "object_distance": object_distance,
        "focal_length": 1.0,
        "object_height": object_height,
        "principal_rays": principal_rays,
        "subtitle": subtitle,
        "annotation_mode": annotation_mode,
        "incident_angle_deg": incident_angle_deg,
        "guide_line_angle_deg": guide_line_angle_deg if guide_line_angle_deg is not None else incident_angle_deg,
        "show_image": show_image,
        "show_focal_labels": False,
    }
    if surface_angle_deg is not None:
        meta["surface_angle_deg"] = surface_angle_deg
    if distance_label:
        meta["distance_label"] = distance_label
    return visual(
        asset_id,
        "optics_ray_diagram",
        title,
        purpose,
        caption,
        template="optics_ray_diagram",
        meta=meta,
    )


def lens_visual(
    asset_id: str,
    title: str,
    purpose: str,
    caption: str,
    *,
    system_type: str,
    subtitle: str,
    object_distance: float,
    focal_length: float,
    object_height: float = 1.0,
    principal_rays: int = 3,
    show_image: bool = True,
    show_focal_labels: bool = True,
) -> Dict[str, Any]:
    return visual(
        asset_id,
        "optics_ray_diagram",
        title,
        purpose,
        caption,
        template="optics_ray_diagram",
        meta={
            "system_type": system_type,
            "object_distance": object_distance,
            "focal_length": focal_length,
            "object_height": object_height,
            "principal_rays": principal_rays,
            "subtitle": subtitle,
            "show_image": show_image,
            "show_focal_labels": show_focal_labels,
        },
    )


def m8_l1_optics_visuals() -> List[Dict[str, Any]]:
    return [
        optics_visual(
            "m8-l1-bounce-panel",
            "Bounce Panel symmetry",
            "Shows equal angles to the Guide Line and the ghost image behind a plane mirror.",
            "The Guide Line, reflected route, and dashed ghost-image extensions stay visibly separate.",
            subtitle="Equal angles at the mirror plus a virtual image behind the surface",
            annotation_mode="bounce_panel",
            object_distance=3.0,
            object_height=1.15,
            incident_angle_deg=35.0,
            principal_rays=3,
        ),
        optics_visual(
            "m8-l1-equal-angles",
            "Equal angles to the Guide Line",
            "Shows that incident and reflected angles match only when both are read from the Guide Line.",
            "Keep the same Guide Line reference for the incoming and outgoing routes.",
            subtitle="Read both routes from the Guide Line, not from the surface",
            annotation_mode="equal_angles",
            object_distance=2.5,
            object_height=1.05,
            incident_angle_deg=35.0,
            principal_rays=2,
            show_image=False,
        ),
        optics_visual(
            "m8-l1-surface-conversion",
            "Surface angle trap vs Guide Line conversion",
            "Shows why a surface angle must be converted before the mirror rule is applied.",
            "A surface-angle reading is useful only after it is turned into the Guide-Line angle.",
            subtitle="20 deg to the surface becomes 70 deg to the Guide Line",
            annotation_mode="surface_conversion",
            object_distance=1.0,
            object_height=1.05,
            incident_angle_deg=70.0,
            surface_angle_deg=20.0,
            guide_line_angle_deg=70.0,
            principal_rays=2,
            show_image=False,
        ),
        optics_visual(
            "m8-l1-ghost-image",
            "Ghost image behind the mirror",
            "Shows that only dashed backward extensions meet behind the mirror.",
            "The reflected routes stay in front of the mirror even though the image is located behind it.",
            subtitle="Backward extensions locate the ghost image without placing real light there",
            annotation_mode="ghost_image",
            object_distance=2.7,
            object_height=1.15,
            incident_angle_deg=32.0,
            principal_rays=3,
        ),
        optics_visual(
            "m8-l1-image-distance",
            "Plane-mirror image distance",
            "Shows that the image forms the same distance behind the mirror as the object is in front.",
            "Object distance and image distance match because the mirror geometry is symmetric.",
            subtitle="A plane mirror places the image at the same perpendicular distance behind the surface",
            annotation_mode="image_distance",
            object_distance=2.2,
            object_height=1.05,
            incident_angle_deg=30.0,
            distance_label="5 cm",
            principal_rays=3,
        ),
    ]


def m8_l2_visuals() -> List[Dict[str, Any]]:
    return [
        wave_visual(
            "m8-l2-bend-gate",
            "Bend Gate boundary turn",
            "Shows one route entering a slower zone and bending toward the Guide Line because the new medium lowers the light speed.",
            "The boundary, Guide Line, medium labels, and refracted route stay visually separate so the bend direction can be explained causally.",
            wave_type="refraction",
            subtitle="Toward the Guide Line in a slower zone, away from it in a faster zone",
        )
    ]


def m8_l3_visuals() -> List[Dict[str, Any]]:
    return [
        lens_visual(
            "m8-l3-gather-lens",
            "Gather Lens to a True Meeting Point",
            "Shows the parallel route, the center route, the far focus, and the real image that forms when actual refracted routes meet.",
            "The focus marker, selected routes, and real image stay readable so the true meeting point is not mistaken for a construction guess.",
            system_type="converging_lens",
            subtitle="A parallel route goes through the far focus while the center route stays undeviated",
            object_distance=3.0,
            focal_length=1.2,
            object_height=1.05,
            principal_rays=3,
        )
    ]


def m8_l4_visuals() -> List[Dict[str, Any]]:
    return [
        lens_visual(
            "m8-l4-spread-lens",
            "Spread Lens and the Ghost Image",
            "Shows real routes spreading after a diverging lens while dashed backward extensions locate the upright virtual image on the object side.",
            "The real routes and the dashed extensions remain visually distinct so the image is read as virtual for the right reason.",
            system_type="diverging_lens",
            subtitle="Parallel routes spread as if they came from the near focus",
            object_distance=2.7,
            focal_length=1.1,
            object_height=1.0,
            principal_rays=3,
        )
    ]


def m8_l5_visuals() -> List[Dict[str, Any]]:
    return [
        wave_visual(
            "m8-l5-critical-angle",
            "Escape edge and critical-angle limit",
            "Compares the below-critical escape case, the exact skimming case, and the above-critical lock-bounce case at one boundary.",
            "The three boundary states stay separated so the critical angle reads as the last possible escape rather than as just a memorized number.",
            wave_type="critical_angle",
            subtitle="Below the limit light escapes, at the limit it skims, above the limit it lock-bounces",
        ),
        wave_visual(
            "m8-l5-optical-fiber",
            "Optical fiber lock-bounce path",
            "Shows repeated total internal reflection trapping the route inside a slower core surrounded by faster cladding.",
            "The zigzag route and the core-cladding labels stay readable so fiber guidance is linked to repeated failed escape, not to a hollow pipe story.",
            wave_type="optical_fiber",
            subtitle="Repeated total internal reflection keeps the route inside the core",
        ),
    ]


def m8_l6_visuals() -> List[Dict[str, Any]]:
    return [
        optics_visual(
            "m8-l6-plane-mirror-ghost",
            "Plane-mirror Ghost Meeting Point",
            "Shows a ghost image behind a mirror so backward extensions, the mirror surface, and the Guide Line can be read as different line roles.",
            "The dashed backward extensions and the real reflected routes stay separate so the mirror image is recognized as virtual.",
            subtitle="Only the backward extensions meet behind the mirror",
            annotation_mode="ghost_image",
            object_distance=2.6,
            object_height=1.1,
            incident_angle_deg=34.0,
            principal_rays=3,
        ),
        lens_visual(
            "m8-l6-converging-real",
            "Converging-lens True Meeting Point",
            "Shows a real image from a converging lens so learners can contrast actual route crossings with dashed-extension cases.",
            "Real refracted routes cross on the far side, so this sketch supports the screen test for a real image.",
            system_type="converging_lens",
            subtitle="Actual routes cross to form a real image that a screen could catch",
            object_distance=2.8,
            focal_length=1.1,
            object_height=1.0,
            principal_rays=3,
        ),
        lens_visual(
            "m8-l6-diverging-ghost",
            "Diverging-lens Ghost Meeting Point",
            "Shows a virtual image from a diverging lens so real routes, focus markers, and dashed extensions can be contrasted with the real-image case.",
            "The image is located by backward extensions rather than by actual route crossings, so the line-role contrast stays explicit.",
            system_type="diverging_lens",
            subtitle="Real routes spread, but backward extensions still locate the ghost image",
            object_distance=2.5,
            focal_length=1.0,
            object_height=1.0,
            principal_rays=3,
        ),
    ]


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


def scaffold(core_idea: str, reasoning: str, check: str, trap: str, analogy_body: str, analogy_check: str, extras: Sequence[Dict[str, str]]) -> Dict[str, Any]:
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
        "The Guide Line, rays, and focal markers do not overlap the explanation text.",
        "Every caption, angle label, and dashed extension remains readable without clipping.",
        "Reference lines, real routes, and dashed extensions are visually distinct enough that they cannot be mistaken for one another at a glance.",
    ]


def glow_route_map(focus: str) -> Dict[str, Any]:
    return {
        "model_name": "Glow-Route Model of Light",
        "focus": focus,
        "comparison": f"The Glow-Route arena keeps reflection, refraction, lenses, lock-bounce, and route sketches in one world while {focus}.",
        "mapping": [
            "Flash Beacon -> light source",
            "Glow-Route -> light ray",
            "Guide Line -> normal",
            "Bounce Panel -> mirror",
            "Bend Gate -> refracting boundary",
            "Slow Zone -> higher refractive index medium",
            "Fast Zone -> lower refractive index medium",
            "Gather Lens -> converging lens",
            "Spread Lens -> diverging lens",
            "Focus Marker -> focal point",
            "Escape Edge -> critical angle",
            "Lock-Bounce -> total internal reflection",
            "Route Sketch -> ray diagram",
            "True Meeting Point -> real image",
            "Ghost Meeting Point -> virtual image",
        ],
        "limit": "The model organizes routes and images, but students still need the formal optics rules and must not treat every line in a ray diagram as literal light.",
        "prediction_prompt": f"Use the Glow-Route model to predict what should happen when {focus}.",
    }


def sim_contract(asset_id: str, concept: str, focus_prompt: str, baseline_case: str, comparison_tasks: Sequence[str], watch_for: str, takeaway: str, controls: Sequence[Tuple[str, str, str]], readouts: Sequence[Tuple[str, str]]) -> Dict[str, Any]:
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


def sim(lab_id: str, title: str, description: str, instructions: Sequence[str], outcomes: Sequence[str], fields: Sequence[str], depth: str) -> Dict[str, Any]:
    return {
        "lab_id": lab_id,
        "title": title,
        "description": description,
        "instructions": list(instructions),
        "outcomes": list(outcomes),
        "fields": list(fields),
        "depth": depth,
    }


def lesson_spec(lesson_id: str, title: str, sim_meta: Dict[str, Any], diagnostic: Sequence[Dict[str, Any]], analogy_text: str, commitment_prompt: str, micro_prompts: Sequence[Dict[str, str]], inquiry: Sequence[Dict[str, str]], recon_prompts: Sequence[str], capsule_prompt: str, capsule_checks: Sequence[Dict[str, Any]], transfer: Sequence[Dict[str, Any]], contract_payload: Dict[str, Any]) -> Dict[str, Any]:
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


def mirror_lesson() -> Dict[str, Any]:
    d = [
        mcq("M8L1_D1", "A Bounce Panel is a...", ["mirror", "lens", "source", "slow zone"], 0, "Bounce Panel means mirror.", ["reflection_equal_angle_confusion"], skill_tags=["reflection_classification"]),
        mcq("M8L1_D2", "Reflection angles are measured from the...", ["Guide Line", "mirror surface", "image", "object"], 0, "Use the normal.", ["angle_from_surface_confusion", "normal_reference_confusion"], skill_tags=["normal_reference"]),
        short("M8L1_D3", "State the mirror angle rule.", ["Angle of incidence equals angle of reflection.", "Incident angle equals reflected angle."], "Tie both angles to the normal.", ["reflection_equal_angle_confusion"], skill_tags=["equal_angles"], acceptance_rules=acceptance_groups(["incident", "incidence"], ["equals", "same as"], ["reflected", "reflection"])),
        mcq("M8L1_D4", "A route strikes at 35 degrees to the Guide Line. Reflected angle?", ["35 degrees", "55 degrees", "70 degrees", "145 degrees"], 0, "Equal angles to the normal.", ["reflection_equal_angle_confusion"], skill_tags=["angle_calculation"]),
        short("M8L1_D5", "A route is 20 degrees to the mirror surface. Angle to the Guide Line?", ["70 degrees", "70"], "Surface and normal differ by 90 degrees.", ["angle_from_surface_confusion"], skill_tags=["surface_to_normal"]),
        mcq("M8L1_D6", "A plane-mirror image appears...", ["the same distance behind as the object is in front", "on the mirror surface", "at the source", "at the focus"], 0, "Plane mirrors give a virtual image behind the surface.", ["mirror_image_surface_confusion", "real_virtual_image_confusion"], skill_tags=["mirror_image_position"]),
        short("M8L1_D7", "Why is the mirror image not on the surface?", ["Because the reflected routes only appear to come from behind the mirror when extended backward.", "Because the image is an apparent meeting point behind the mirror, not on the surface."], "Use apparent-path language.", ["mirror_image_surface_confusion", "ray_diagram_literal_confusion"], skill_tags=["virtual_extension"], acceptance_rules=acceptance_groups(["appear", "apparent", "seem"], ["come from", "meet"], ["behind the mirror", "behind"], ["not", "rather than"], ["surface"])),
        mcq("M8L1_D8", "If the route arrives along the Guide Line, it...", ["retraces the same line", "turns 90 degrees", "becomes virtual", "speeds up"], 0, "Zero in, zero out.", ["reflection_equal_angle_confusion"], skill_tags=["special_case_reflection"]),
    ]
    c = [
        short("M8L1_C1", "Why does the Guide Line matter more than the surface in reflection questions?", ["Because the reflection rule compares angles to the normal, not to the surface.", "Because the Guide Line is the reference line for incident and reflected angles."], "Use reference-line language.", ["angle_from_surface_confusion", "normal_reference_confusion"], skill_tags=["normal_reference"], acceptance_rules=acceptance_groups(["guide line", "normal"], ["reference", "measured from"], ["incident", "reflected"], ["not", "rather than"], ["surface"])),
        mcq("M8L1_C2", "What makes a plane-mirror image virtual?", ["The reflected routes do not actually meet behind the mirror", "The mirror is flat", "The object is bright", "The normal is vertical"], 0, "Virtual images come from apparent intersections.", ["real_virtual_image_confusion"], skill_tags=["real_vs_virtual"]),
        mcq("M8L1_C3", "Object 6 cm in front of a plane mirror. Image?", ["6 cm behind", "3 cm behind", "12 cm behind", "on the mirror"], 0, "Same distance behind.", ["mirror_image_surface_confusion"], skill_tags=["mirror_image_position"]),
        short("M8L1_C4", "Why are dashed lines drawn behind a mirror?", ["They are backward extensions that show where the reflected routes appear to come from.", "They locate the apparent image even though no real light travels there."], "Extensions are geometry tools.", ["ray_diagram_literal_confusion"], skill_tags=["virtual_extension"], acceptance_rules=acceptance_groups(["backward", "extension", "dashed"], ["appear", "seem"], ["come from", "locate"], ["no real light", "not actual light"])),
        mcq("M8L1_C5", "An object is 4 cm in front of a plane mirror. Object-image separation?", ["8 cm", "4 cm", "2 cm", "16 cm"], 0, "Add object distance and image distance.", ["mirror_image_surface_confusion"], skill_tags=["mirror_image_position"]),
        short("M8L1_C6", "Why is measuring from the mirror surface risky?", ["Because the reflection law is written using the normal, so a surface angle must be converted first.", "Because the equal-angle rule uses the Guide Line rather than the surface."], "Convert surface angles first.", ["angle_from_surface_confusion", "normal_reference_confusion"], skill_tags=["surface_to_normal"], acceptance_rules=acceptance_groups(["reflection law", "equal-angle rule"], ["normal", "guide line"], ["convert", "converted"], ["surface"])),
    ]
    t = [
        mcq("M8L1_M1", "62 degrees to the Guide Line in. Reflected angle?", ["62 degrees", "28 degrees", "124 degrees", "31 degrees"], 0, "Equal angles.", ["reflection_equal_angle_confusion"], skill_tags=["angle_calculation"]),
        short("M8L1_M2", "15 degrees to the surface equals what incident angle to the Guide Line?", ["75 degrees", "75"], "Use 90 - 15.", ["angle_from_surface_confusion"], skill_tags=["surface_to_normal"]),
        mcq("M8L1_M3", "A pair is always equal in plane reflection:", ["incident angle and reflected angle to the Guide Line", "object height and angle", "image distance and angle", "brightness and tilt"], 0, "Equal angles to the normal.", ["reflection_equal_angle_confusion"], skill_tags=["equal_angles"]),
        short("M8L1_M4", "Why is the mirror image a Ghost Meeting Point?", ["Because the reflected routes only appear to meet when extended backward.", "Because the image is found from apparent backward extensions rather than real crossings."], "Use apparent-meeting language.", ["real_virtual_image_confusion", "ray_diagram_literal_confusion"], skill_tags=["real_vs_virtual"], acceptance_rules=acceptance_groups(["appear", "apparent"], ["meet", "come from"], ["backward", "extension"], ["not", "rather than"], ["real"])),
        mcq("M8L1_M5", "30 degrees to the surface means which normal angle?", ["60 degrees", "30 degrees", "90 degrees", "120 degrees"], 0, "Convert to the normal.", ["angle_from_surface_confusion"], skill_tags=["surface_to_normal"]),
        mcq("M8L1_M6", "Best first move in a mirror sketch?", ["Draw the Guide Line first", "Draw dashed lines first", "Ignore the normal", "Start from the surface angle only"], 0, "Protect the reference line.", ["normal_reference_confusion"], skill_tags=["diagram_habits"]),
        short("M8L1_M7", "Why does the mirror image stay the same distance behind the surface?", ["Because the equal-angle geometry makes the backward extensions meet at the symmetric point behind the mirror.", "Because the reflected routes are symmetric about the Guide Line, so the apparent image is equally far behind."], "Use symmetry language.", ["mirror_image_surface_confusion"], skill_tags=["mirror_image_position"], acceptance_rules=acceptance_groups(["symmetric", "symmetry", "same distance"], ["behind"], ["guide line", "mirror"], ["extension", "apparent image"])),
        mcq("M8L1_M8", "Which line is a reference, not a beam?", ["the Guide Line", "the reflected route", "the incident route", "the object ray"], 0, "The normal is a reference line.", ["normal_reference_confusion", "ray_diagram_literal_confusion"], skill_tags=["diagram_roles"]),
    ]
    return lesson_spec("M8_L1", "Bounce Panels and Guide-Line Angles", sim("m8_mirror_match_lab", "Mirror Match lab", "Use equal-angle mirror geometry and mirror-image symmetry.", ["Set one incident route.", "Draw the Guide Line.", "Compare equal angles and image position."], ["Explain reflection from the normal.", "Place a plane-mirror image.", "Convert surface and normal angles."], ["incident_angle_deg", "surface_angle_deg", "reflected_angle_deg", "image_offset_cm"], "Normal-first mirror geometry."), d, "A Bounce Panel reflects the Glow-Route symmetrically around the Guide Line.", "Name the Guide Line before you trust any mirror angle.", [prompt_block("What line sets the mirror angles?", "The Guide Line normal."), prompt_block("Why can the image be behind the mirror?", "Think apparent backward extension.")], [prompt_block("Increase the incident angle and compare the reflected angle.", "Keep the same reference line."), prompt_block("Compare surface-angle and Guide-Line readings.", "They are not the same thing.")], ["Explain why the Guide Line is the trusted mirror reference.", "Explain why the mirror image is behind the surface without real light there."], "Keep the equal-angle rule and the status of dashed extensions visible before reading any mirror sketch.", c, t, contract(concept_targets=["Explain plane reflection as equal angles to the normal.", "Convert between surface and normal angles.", "Describe plane-mirror images as virtual."], core_concepts=["Plane reflection obeys an equal-angle rule around the normal.", "The normal is the reference line for reflection angles.", "A plane-mirror image is a virtual image the same distance behind the mirror as the object is in front.", "Backward extensions in a mirror sketch are not real light paths."], prerequisite_lessons=["F2_L6"], misconception_focus=["angle_from_surface_confusion", "normal_reference_confusion", "reflection_equal_angle_confusion", "mirror_image_surface_confusion", "ray_diagram_literal_confusion", "real_virtual_image_confusion"], formulas=[relation("angle of incidence = angle of reflection", "Plane reflection keeps equal angles to the normal.", ["degrees"], "Use for a flat mirror.")], representations=[representation("words", "States the mirror rule plainly."), representation("diagram", "Shows the Guide Line, incident route, reflected route, and image extension."), representation("formula", "Compresses the equal-angle rule.")], analogy_map=glow_route_map("the class is comparing reflection angles and plane-mirror ghost images"), worked_examples=[worked("A route arrives at 35 degrees to the Guide Line. Find the reflected angle.", ["Read the angle from the Guide Line.", "Apply the equal-angle rule.", "Use the same reference line in the answer."], "35 degrees", "Plane reflection keeps equal angles to the normal.", "This anchors the mirror rule numerically."), worked("A route is 20 degrees to the surface. Find the incident angle to the Guide Line.", ["Note that surface and normal differ by 90 degrees.", "Subtract 20 from 90.", "Use the converted angle in the rule."], "70 degrees", "Mirror laws use the normal, so surface angles must be converted.", "This blocks the surface-angle trap."), worked("An object is 5 cm in front of a plane mirror. Where is the image?", ["Use plane-mirror symmetry.", "Place the image the same distance behind the mirror.", "Remember that the lines behind the mirror are backward extensions."], "5 cm behind the mirror", "The image is virtual and located by symmetric backward extensions.", "This keeps geometry and image type connected.")], visual_assets=m8_l1_optics_visuals(), animation_assets=[animation("m8-l1-mirror-bounce", "reflection", "Mirror bounce", "Shows one route reflecting and the image appearing behind the mirror.")], simulation_contract=sim_contract("m8-l1-mirror-match-lab", "reflection", "How does the Bounce Panel keep the route symmetric around the Guide Line?", "Start with one diagonal route striking a flat mirror and display the Guide Line first.", ["Change the incident angle and compare the reflected angle.", "Convert a surface angle into the correct normal-based angle."], "Measure from the Guide Line and do not label the dashed image lines as real light.", "Plane reflection is a normal-based symmetry rule.", [("incident_angle", "Incident angle", "Changes the incoming geometry."), ("mirror_tilt", "Mirror tilt", "Moves the Guide Line so the learner must keep the correct reference."), ("object_offset", "Object distance", "Shows the ghost-image placement.")], [("Incident angle", "Incoming angle to the Guide Line."), ("Reflected angle", "Outgoing angle to the Guide Line."), ("Ghost image position", "Apparent image behind the mirror.")]), reflection_prompts=["Why must mirror angles be measured from the Guide Line?", "Why is the plane-mirror image a ghost position rather than a real crossing?"], mastery_skills=["reflection_classification", "normal_reference", "equal_angles", "surface_to_normal", "mirror_image_position"], variation_plan={"diagnostic": "Fresh attempts rotate between normal-reference, angle, and mirror-image stems.", "concept_gate": "Concept checks vary between equal-angle reasoning and ghost-image explanation.", "mastery": "Mastery mixes angle conversion, plane-mirror geometry, and dashed-extension questions before repeating any stem."}, scaffold_support=scaffold("Reflection at a plane mirror is a symmetry rule around the normal.", "Draw the Guide Line first, then compare the incoming and outgoing routes to that line.", "If a route arrives at 40 degrees to the Guide Line, what reflected angle should you expect?", "Do not treat a surface angle as if it were already the incident angle in the reflection law.", "The Bounce Panel makes the reflection geometry visible around the Guide Line while the image appears from backward extensions.", "Which lines in the sketch are real routes and which are only extensions?", [extra_section("Surface angle trap", "Surface angles can be useful, but they must be converted to normal-based angles before the rule is used.", "Why is a 20 degree surface angle not automatically the incident angle?"), extra_section("Ghost image clue", "A plane-mirror image is a ghost meeting point because the reflected routes only appear to come from behind the mirror.", "What makes the mirror image virtual?")]), visual_clarity_checks=visual_checks("reflection")))



def refraction_lesson() -> Dict[str, Any]:
    d = [
        mcq("M8L2_D1", "A Bend Gate is a...", ["refracting boundary", "mirror", "screen", "source"], 0, "Bend Gate means refracting boundary.", ["refraction_speed_change_confusion"], skill_tags=["refraction_classification"]),
        mcq("M8L2_D2", "Fast to slow medium means the route bends...", ["toward the Guide Line", "away from the Guide Line", "back to the source", "nowhere"], 0, "Slower medium means toward the normal.", ["toward_away_normal_confusion"], skill_tags=["toward_normal_rule"]),
        short("M8L2_D3", "Why does the route bend at a Bend Gate?", ["Because the light speed changes between the two media.", "Because the route enters a medium where light travels at a different speed."], "Use speed-change language.", ["refraction_speed_change_confusion"], skill_tags=["speed_change_reasoning"], acceptance_rules=acceptance_groups(["speed", "travel"], ["changes", "different"], ["medium", "boundary"])),
        mcq("M8L2_D4", "Glass to air means the route bends...", ["away from the Guide Line", "toward the Guide Line", "by equal-angle reflection", "not at all"], 0, "Slow to fast means away from the normal.", ["toward_away_normal_confusion"], skill_tags=["away_normal_rule"]),
        short("M8L2_D5", "Why is 'the lens pulls the route to the middle' weak?", ["Because the route bends at medium boundaries where the speed changes, not because the middle pulls it.", "Because refraction happens at the surfaces, not by a pull from the lens center."], "Keep the cause at the boundary.", ["lens_middle_pull_confusion", "refraction_speed_change_confusion"], skill_tags=["boundary_cause"], acceptance_rules=acceptance_groups(["boundary", "surface", "medium"], ["speed", "changes", "different"], ["not", "rather than"], ["pull", "middle"])),
        mcq("M8L2_D6", "Refraction angles are measured from the...", ["Guide Line", "surface", "axis only", "image"], 0, "Still use the normal.", ["normal_reference_confusion"], skill_tags=["normal_reference"]),
        mcq("M8L2_D7", "If speed did not change across the boundary, the route would...", ["not need to bend", "always bend toward the normal", "always bend away", "become virtual"], 0, "Refraction is driven by speed change.", ["refraction_speed_change_confusion"], skill_tags=["speed_change_reasoning"]),
        mcq("M8L2_D8", "A lens bends routes at...", ["entry and exit surfaces", "the middle only", "the object", "the screen"], 0, "A lens is two boundaries.", ["lens_middle_pull_confusion", "lens_ray_rule_confusion"], skill_tags=["double_refraction"]),
    ]
    c = [
        short("M8L2_C1", "How does slowing down connect to bending toward the Guide Line?", ["If light slows in the new medium, the route bends toward the normal.", "A slower zone makes the refracted route turn toward the Guide Line."], "Tie the direction to speed change.", ["toward_away_normal_confusion"], skill_tags=["toward_normal_rule"], acceptance_rules=acceptance_groups(["slow", "slower"], ["toward"], ["guide line", "normal"])),
        mcq("M8L2_C2", "Water to air gives which turn?", ["away from the Guide Line", "toward the Guide Line", "equal-angle reflection", "no change"], 0, "Slow to fast means away.", ["toward_away_normal_confusion"], skill_tags=["away_normal_rule"]),
        short("M8L2_C3", "Why should refraction angles be measured from the Guide Line?", ["Because the normal is the standard reference line for incident and refracted routes.", "Because the toward-normal and away-normal rules use the Guide Line."], "Use one shared reference line.", ["normal_reference_confusion"], skill_tags=["normal_reference"], acceptance_rules=acceptance_groups(["normal", "guide line"], ["reference", "measured from"], ["incident", "refracted"])),
        mcq("M8L2_C4", "What mainly separates reflection from refraction?", ["Refraction is a turn in a new medium where speed changes", "Refraction is always a bounce", "Refraction ignores the normal", "Refraction happens only at mirrors"], 0, "Reflection bounces; refraction turns in a new medium.", ["refraction_speed_change_confusion", "reflection_equal_angle_confusion"], skill_tags=["refraction_classification"]),
        short("M8L2_C5", "Why can a lens bend light twice?", ["Because it refracts the route when light enters and refracts again when light leaves.", "Because a lens is made of two refracting surfaces."], "Entry and exit both matter.", ["lens_ray_rule_confusion", "lens_middle_pull_confusion"], skill_tags=["double_refraction"], acceptance_rules=acceptance_groups(["enter", "entry"], ["leave", "exit"], ["refract", "bend"], ["two", "surfaces", "boundaries"])),
        mcq("M8L2_C6", "If a learner reads the angle from the surface instead of the Guide Line, the likely problem is...", ["the bend direction may be judged wrongly", "the image becomes brighter", "the lens becomes a mirror", "the boundary disappears"], 0, "Wrong reference lines create wrong bend judgments.", ["angle_from_surface_confusion", "normal_reference_confusion"], skill_tags=["diagram_habits"]),
    ]
    t = [
        mcq("M8L2_M1", "Air to glass means the refracted angle becomes...", ["smaller to the Guide Line", "larger to the Guide Line", "equal to the surface angle", "zero every time"], 0, "Fast to slow means toward the normal.", ["toward_away_normal_confusion"], skill_tags=["toward_normal_rule"]),
        short("M8L2_M2", "State what happens when light leaves glass for air.", ["It bends away from the Guide Line because it speeds up.", "It bends away from the normal because the new medium is faster."], "Give both direction and reason.", ["toward_away_normal_confusion", "refraction_speed_change_confusion"], skill_tags=["away_normal_rule"], acceptance_rules=acceptance_groups(["away"], ["guide line", "normal"], ["faster", "speeds up"], ["air", "new medium"])),
        mcq("M8L2_M3", "Which sentence keeps the cause of refraction correct?", ["The route bends because the light speed changes across the boundary", "The route bends because the middle of the lens pulls it", "The route bends because mirrors always act first", "The route bends because the object is bright"], 0, "Speed change at the boundary is the cause.", ["refraction_speed_change_confusion", "lens_middle_pull_confusion"], skill_tags=["boundary_cause"]),
        short("M8L2_M4", "Why is a lens best described as a pair of Bend Gates?", ["Because the route refracts at the first surface and again at the second surface.", "Because a lens changes the route at entry and exit rather than by pulling in the middle."], "A lens is two refractions.", ["lens_middle_pull_confusion", "lens_ray_rule_confusion"], skill_tags=["double_refraction"], acceptance_rules=acceptance_groups(["first", "entry"], ["second", "exit"], ["refract", "bend"], ["middle", "pull", "not"])),
        mcq("M8L2_M5", "If the next medium had the same light speed, the boundary would cause...", ["no refraction turn", "a guaranteed bend toward the normal", "a guaranteed bend away", "total internal reflection"], 0, "Without a speed change there is no reason to bend.", ["refraction_speed_change_confusion"], skill_tags=["speed_change_reasoning"]),
        mcq("M8L2_M6", "What should you ask first at a Bend Gate?", ["Is the next zone slower or faster?", "Is the surface shiny?", "Is there a screen?", "Is the object inverted?"], 0, "The first prediction clue is the new medium speed.", ["refraction_speed_change_confusion"], skill_tags=["prediction_habit"]),
        short("M8L2_M7", "Why is the Guide Line still important in refraction?", ["Because the refracted angle is also read from the normal.", "Because the Guide Line is still the standard angle reference at the boundary."], "Keep the same reference-line habit.", ["normal_reference_confusion"], skill_tags=["normal_reference"], acceptance_rules=acceptance_groups(["guide line", "normal"], ["reference", "measured from"], ["refracted", "incident"])),
        mcq("M8L2_M8", "Water to air with a route farther from the Guide Line after crossing is...", ["consistent with speeding up into a faster medium", "evidence of a mirror", "proof of a plane-mirror image", "impossible"], 0, "Slow to fast means away from the normal.", ["toward_away_normal_confusion"], skill_tags=["angle_comparison"]),
    ]
    return lesson_spec("M8_L2", "Bend Gates, Fast Zones, and Slow Zones", sim("m8_bend_gate_lab", "Bend Gate lab", "Compare fast-to-slow and slow-to-fast boundaries.", ["Start with air to glass.", "Reverse to glass to air.", "Keep the Guide Line visible both times."], ["Explain refraction as a speed-change effect.", "Predict toward-normal and away-normal bends.", "Describe a lens as two refractions."], ["incident_angle_deg", "speed_ratio", "refracted_angle_deg", "boundary_case"], "Speed-zone boundary reasoning."), d, "A Glow-Route turns at a Bend Gate because the new zone changes how fast light travels.", "Before calling the bend direction, decide whether the next zone is slower or faster.", [prompt_block("If the next zone is slower, which way does the route turn?", "Toward the Guide Line."), prompt_block("Why is the lens-middle-pull story weak?", "The turn happens at the boundaries.")], [prompt_block("Compare air to glass with glass to air.", "One turns toward the Guide Line; the other turns away."), prompt_block("Hold the incident angle steady while you change the speed ratio.", "The bend follows the medium change.")], ["Explain the cause of refraction using speed-change language.", "Explain why a lens bends at entry and exit surfaces."], "Keep the speed-zone cause and the Guide Line reference visible before you judge the bend direction.", c, t, contract(concept_targets=["Explain refraction as a speed-change effect.", "Predict toward-normal and away-normal bends.", "Describe a lens as a pair of refracting boundaries."], core_concepts=["Refraction is a direction change caused by a speed change at a boundary.", "Entering a slower medium bends the route toward the normal.", "Entering a faster medium bends the route away from the normal.", "A lens bends routes at entry and exit surfaces rather than by pulling them toward the middle."], prerequisite_lessons=["M8_L1"], misconception_focus=["refraction_speed_change_confusion", "toward_away_normal_confusion", "normal_reference_confusion", "angle_from_surface_confusion", "lens_middle_pull_confusion", "lens_ray_rule_confusion"], formulas=[relation("slower medium -> toward the normal; faster medium -> away from the normal", "Refraction direction follows how the light speed changes across the boundary.", ["degrees"], "Use when comparing incident and refracted routes.")], representations=[representation("words", "Explains the speed-change reason."), representation("diagram", "Shows incident and refracted routes with the Guide Line."), representation("formula", "Compresses the toward-normal and away-normal rule.")], analogy_map=glow_route_map("the class is comparing fast zones, slow zones, and refracting boundaries"), worked_examples=[worked("A route goes from air into glass. Which way does it bend?", ["Identify air as faster and glass as slower.", "Use the speed-change rule.", "State the turn relative to the Guide Line."], "Toward the Guide Line", "Entering a slower medium bends the route toward the normal.", "This gives the basic bend direction a clear anchor."), worked("A route leaves glass and enters air. Which way does it bend?", ["Identify glass as slower and air as faster.", "Use the reverse speed-change rule.", "State the turn relative to the Guide Line."], "Away from the Guide Line", "Leaving a slower medium for a faster one bends the route away from the normal.", "This secures the reverse case."), worked("A student says the lens pulls the route toward the middle. Correct it.", ["Look for where the direction changes.", "Notice the entry and exit surfaces.", "State the cause as a medium change at each surface."], "The lens bends routes because light refracts at its two surfaces.", "A lens is two boundary turns, not a middle pull.", "This blocks a persistent lens misconception.")], visual_assets=[visual("m8-l2-bend-gate", "refraction", "Fast and slow zones", "Shows toward-normal and away-normal cases with the Guide Line.", "The speed labels and the Guide Line should stay visible together.")], animation_assets=[animation("m8-l2-zone-turn", "refraction", "Boundary turn", "Shows the route bend toward the Guide Line on entry to a slower zone and away on exit to a faster zone.")], simulation_contract=sim_contract("m8-l2-bend_gate_lab", "refraction", "What does the new zone do to route speed, and what bend direction should that cause?", "Start with an air-to-glass style boundary and keep the Guide Line visible.", ["Compare fast-to-slow with slow-to-fast at the same incident angle.", "Compare a surface-angle reading with the correct Guide-Line reading."], "Explain the bend with speed change and the normal, not with a lens-center pull.", "Refraction is a speed-zone turn and lenses work because routes refract at entry and exit surfaces.", [("incident_angle", "Incident angle", "Changes the incoming geometry."), ("speed_ratio", "Zone speed ratio", "Changes whether the new medium is faster or slower."), ("boundary_case", "Boundary direction", "Switches entering a slower medium and leaving it.")], [("Refracted angle", "Outgoing angle to the Guide Line."), ("Zone label", "Shows faster or slower medium."), ("Bend direction", "Shows toward or away from the Guide Line.")]), reflection_prompts=["Why does a Glow-Route turn at a Bend Gate?", "Why is a lens better described as two boundary turns than a middle pull?"], mastery_skills=["refraction_classification", "toward_normal_rule", "away_normal_rule", "speed_change_reasoning", "double_refraction"], variation_plan={"diagnostic": "Fresh attempts rotate between fast-to-slow, slow-to-fast, and weak-explanation stems.", "concept_gate": "Concept checks vary between direction prediction and cause explanation.", "mastery": "Mastery mixes media pairs, Guide-Line reasoning, and lens-as-two-boundaries prompts before repeating stems."}, scaffold_support=scaffold("Refraction is a boundary turn caused by a speed change in the new medium.", "Ask two questions in order: is the new medium slower or faster, and which line is the Guide Line?", "If light enters a slower medium, which way should the route turn relative to the Guide Line?", "Do not describe the bend as if the route is being pulled toward the lens middle.", "The Bend Gate keeps the route, the Guide Line, and the speed labels in one picture so the direction rule feels causal rather than magical.", "What changes first at the boundary: the route speed or the lens center?", [extra_section("Toward and away", "Toward the Guide Line means a smaller angle to the normal; away means a larger angle to the normal.", "Which phrase belongs to a route entering a slower zone?"), extra_section("Two bends in a lens", "A thin lens can be treated as two refracting surfaces, so the route changes direction at entry and then again at exit.", "Why is a lens more than one single bend?")]), visual_clarity_checks=visual_checks("refraction")))


def gather_lens_lesson() -> Dict[str, Any]:
    d = [
        mcq("M8L3_D1", "A Gather Lens is a...", ["converging lens", "diverging lens", "mirror", "fiber"], 0, "Gather Lens means converging lens.", ["lens_ray_rule_confusion"], skill_tags=["lens_classification"]),
        mcq("M8L3_D2", "A route parallel to the axis through a converging lens goes...", ["through the far Focus Marker", "through the near Focus Marker", "straight back", "along the surface"], 0, "Use the parallel-ray rule.", ["lens_ray_rule_confusion"], skill_tags=["converging_parallel_ray"]),
        mcq("M8L3_D3", "In the thin-lens model, the center ray is treated as...", ["undeviated", "reflected", "always through the focus first", "virtual"], 0, "The center ray is taken as straight.", ["lens_ray_rule_confusion"], skill_tags=["central_ray_rule"]),
        short("M8L3_D4", "What makes a True Meeting Point a real image?", ["The actual refracted routes meet there.", "A real image forms where real routes actually cross."], "Real images use actual crossings.", ["real_virtual_image_confusion"], skill_tags=["real_image_definition"], acceptance_rules=acceptance_groups(["real", "actual"], ["routes", "rays"], ["meet", "cross"])),
        mcq("M8L3_D5", "Object at 2F for a converging lens means image at...", ["2F on the far side and same size", "the near focus only", "the lens center", "no image"], 0, "Use the standard 2F case.", ["lens_ray_rule_confusion"], skill_tags=["converging_special_case"]),
        mcq("M8L3_D6", "Object beyond 2F means image...", ["between F and 2F on the far side", "between the lens and F on the near side", "at the mirror surface", "behind the object"], 0, "Beyond 2F gives a smaller real image between F and 2F.", ["lens_ray_rule_confusion"], skill_tags=["image_region_reasoning"]),
        short("M8L3_D7", "Why is 'the lens stores the image inside itself' weak?", ["Because the lens redirects many routes so they meet at an image point; it does not store the image inside.", "Because the image forms where refracted routes meet, not as something kept inside the lens."], "Use route-redirection language.", ["lens_middle_pull_confusion", "real_virtual_image_confusion"], skill_tags=["image_formation_reasoning"], acceptance_rules=acceptance_groups(["redirect", "refract", "bend"], ["routes", "rays"], ["meet", "cross"], ["not", "rather than"], ["store", "inside"])),
        mcq("M8L3_D8", "Object between F and 2F means image...", ["beyond 2F and enlarged", "between F and 2F and smaller", "virtual and same size", "on the lens"], 0, "Between F and 2F gives a larger real image beyond 2F.", ["lens_ray_rule_confusion"], skill_tags=["image_region_reasoning"]),
    ]
    c = [
        short("M8L3_C1", "Why are only a few selected routes needed in a converging-lens sketch?", ["Because a few rule-based routes are enough to predict where the many real routes meet.", "Because the selected rays stand in for the full bundle and locate the image efficiently."], "A route sketch is a predictive map.", ["ray_diagram_literal_confusion", "lens_ray_rule_confusion"], skill_tags=["ray_selection"], acceptance_rules=acceptance_groups(["few", "selected"], ["predict", "locate"], ["many", "bundle"], ["meet", "image"])),
        mcq("M8L3_C2", "Which route rule belongs to a converging lens?", ["parallel in -> through far focus out", "parallel in -> appears from near focus", "incident angle equals reflected angle", "no route can go straight through"], 0, "That is the key converging-lens rule.", ["lens_ray_rule_confusion"], skill_tags=["converging_parallel_ray"]),
        mcq("M8L3_C3", "What makes this image a True Meeting Point?", ["The real refracted routes actually meet on the far side", "The lens is thick", "The object is bright", "The axis is horizontal"], 0, "Real images use actual route intersections.", ["real_virtual_image_confusion"], skill_tags=["real_image_definition"]),
        short("M8L3_C4", "Why is the center route treated as undeviated?", ["Because the thin-lens model uses it as a straight reference route through the lens center.", "Because in the standard ray diagram the center ray is taken as passing straight through the lens."], "This is a model rule that keeps the sketch efficient.", ["lens_ray_rule_confusion"], skill_tags=["central_ray_rule"], acceptance_rules=acceptance_groups(["center", "central"], ["straight", "undeviated"], ["thin-lens", "model", "ray diagram"])),
        mcq("M8L3_C5", "A converging-lens image beyond 2F from an object beyond 2F would be...", ["wrong", "normal", "required", "a mirror effect"], 0, "Beyond 2F should give an image between F and 2F.", ["lens_ray_rule_confusion"], skill_tags=["image_region_reasoning"]),
        short("M8L3_C6", "Why is a real converging-lens image different from a plane-mirror image?", ["Because real routes actually cross at the converging-lens image, while a plane-mirror image comes from apparent backward extensions.", "Because a real image is a true meeting point and a mirror image is a ghost meeting point."], "Contrast actual crossings with apparent ones.", ["real_virtual_image_confusion"], skill_tags=["real_vs_virtual"], acceptance_rules=acceptance_groups(["real", "actual"], ["routes", "rays"], ["cross", "meet"], ["mirror", "apparent", "extension", "ghost"])),
    ]
    t = [
        mcq("M8L3_M1", "Useful pair for locating a real image quickly:", ["parallel ray plus center ray", "two reflected rays", "surface angle plus object height", "two dashed extensions"], 0, "Use selected key rays.", ["lens_ray_rule_confusion"], skill_tags=["ray_selection"]),
        short("M8L3_M2", "Describe the 2F converging-lens case.", ["Real, inverted, same size, at 2F on the far side.", "It forms a same-size real image at 2F on the other side."], "Use the standard 2F anchor.", ["lens_ray_rule_confusion"], skill_tags=["converging_special_case"], acceptance_rules=acceptance_groups(["real"], ["2F", "two focal lengths", "far side", "other side"], ["same size"])),
        mcq("M8L3_M3", "Object between F and 2F means image...", ["real, inverted, enlarged, beyond 2F", "real, upright, smaller, between F and 2F", "virtual, upright, smaller", "none"], 0, "Use the between-F-and-2F case.", ["lens_ray_rule_confusion"], skill_tags=["image_region_reasoning"]),
        short("M8L3_M4", "Why can a screen catch the image from a converging lens in this case?", ["Because the actual refracted routes meet at a real image point.", "Because the image is a True Meeting Point where real rays cross."], "Screenability is evidence of a real image.", ["real_virtual_image_confusion"], skill_tags=["real_image_definition"], acceptance_rules=acceptance_groups(["screen", "catch"], ["real", "actual"], ["routes", "rays"], ["meet", "cross"])),
        mcq("M8L3_M5", "A route parallel to the axis through a converging lens should next go...", ["through the far Focus Marker", "through the near Focus Marker", "straight back", "along the surface"], 0, "That is the parallel-ray rule.", ["lens_ray_rule_confusion"], skill_tags=["converging_parallel_ray"]),
        mcq("M8L3_M6", "Which statement about a Gather Lens is strongest?", ["It redirects routes so they meet at an image point", "It stores the image inside the glass", "It pulls routes with its middle", "It creates only virtual images"], 0, "Use route-redirection language.", ["lens_middle_pull_confusion"], skill_tags=["image_formation_reasoning"]),
        short("M8L3_M7", "Why is a few-ray sketch still useful even though many rays exist?", ["Because the chosen routes obey the same geometry and locate the image efficiently.", "Because a small set of rule-based routes predicts the same meeting point as the full bundle."], "Ray diagrams are efficient maps.", ["ray_diagram_literal_confusion"], skill_tags=["ray_selection"], acceptance_rules=acceptance_groups(["few", "small set", "chosen"], ["same geometry", "predict"], ["meeting point", "image"], ["many", "full bundle"])),
        mcq("M8L3_M8", "Object beyond 2F should give an image that is...", ["real, smaller, between F and 2F", "virtual, upright, between the lens and F", "same size at 2F", "on the object side"], 0, "Use the standard beyond-2F case.", ["lens_ray_rule_confusion"], skill_tags=["image_region_reasoning"]),
    ]
    return lesson_spec("M8_L3", "Gather Lenses and True Meeting Points", sim("m8_gather_lens_lab", "Gather Lens lab", "Trace the key routes for a converging lens and watch where actual routes meet.", ["Start with the object outside F.", "Use the parallel route and the center route.", "Compare beyond-2F and between-F-and-2F cases."], ["Apply converging-lens route rules.", "Identify True Meeting Points.", "Use F and 2F anchor cases."], ["object_distance_f", "focal_length_cm", "image_region", "image_type"], "Selected-ray converging-lens reasoning."), d, "A Gather Lens is shaped so selected Glow-Routes head toward a real crossing on the far side.", "Before drawing a converging-lens sketch, decide which routes are most informative and whether the image is a real crossing.", [prompt_block("What happens to a parallel route through a Gather Lens?", "It goes through the far Focus Marker."), prompt_block("What tells you the image is a True Meeting Point?", "Actual routes meet there.")], [prompt_block("Move the object from beyond 2F to between F and 2F.", "Watch the image region change."), prompt_block("Compare selected rays with the full bundle idea.", "A few key rays still locate the image.")], ["Explain how a Gather Lens forms a True Meeting Point.", "Explain why selected rays are enough to predict the image region."], "Keep the key ray rules and the meaning of a real crossing visible before naming the image.", c, t, contract(concept_targets=["Use key converging-lens route rules.", "Distinguish True Meeting Points from Ghost Meeting Points.", "Use F and 2F cases to reason about image position and size."], core_concepts=["A converging lens redirects routes so real routes can meet on the far side.", "A route parallel to the axis emerges through the far focus.", "A center route is treated as undeviated in the thin-lens model.", "A real image is a true meeting point where actual routes cross."], prerequisite_lessons=["M8_L2"], misconception_focus=["lens_ray_rule_confusion", "lens_middle_pull_confusion", "real_virtual_image_confusion", "ray_diagram_literal_confusion"], formulas=[relation("parallel in -> through far focus out; center ray -> straight through", "Converging-lens route rules let a few selected rays locate a real image.", ["diagram rules"], "Use in thin-lens ray diagrams.")], representations=[representation("words", "Names the key converging-lens rules."), representation("diagram", "Shows selected rays crossing to form a real image."), representation("formula", "Compresses the route rules.")], analogy_map=glow_route_map("the class is tracing converging-lens routes to a true meeting point"), worked_examples=[worked("Object at 2F in front of a converging lens. Where is the image?", ["Recall the standard 2F case.", "Trace a parallel ray and a center ray.", "Read the crossing point on the far side."], "At 2F on the far side, same size and real", "The 2F geometry makes the selected routes meet at 2F on the other side.", "This gives the lesson a stable anchor case."), worked("Object beyond 2F. What image region fits?", ["Trace the parallel ray through the far focus.", "Trace the center ray straight through.", "Read the crossing region."], "Between F and 2F, real and smaller", "Beyond-2F geometry makes the routes cross between F and 2F.", "This builds comparison language around the anchor case."), worked("A student says the lens stores the image inside itself. Correct it.", ["Look for where the routes meet.", "Notice that the crossing point is beyond the lens, not inside it.", "State the image as a result of route redirection."], "The lens redirects routes; the real image forms where those routes meet.", "A converging lens creates image geometry by refraction, not by storing a picture inside itself.", "This keeps image formation tied to route behavior.")], visual_assets=[visual("m8-l3-gather-lens", "converging_lens", "Gather Lens routes", "Shows the parallel route, center route, focus marker, and real image region.", "The key routes and the true meeting point should be easy to distinguish.")], animation_assets=[animation("m8-l3-gather-routes", "converging_lens", "Routes converge", "Shows selected routes meeting at a true image point on the far side of a converging lens.")], simulation_contract=sim_contract("m8-l3-gather-lens-lab", "converging_lens", "Which key routes should you trace, and where do the real routes meet?", "Start with the object outside the focus so a real image forms.", ["Move the object from beyond 2F to between F and 2F.", "Compare the parallel route with the center route."], "Treat the selected rays as efficient prediction tools rather than as the only rays that exist.", "A Gather Lens forms a true image because actual refracted routes meet.", [("object_distance", "Object distance", "Changes the image region and size."), ("focal_length", "Focal length", "Moves the focus markers."), ("route_selector", "Key route overlay", "Keeps the selected rays distinct from the full bundle idea.")], [("Image region", "Shows where the real image lands relative to F and 2F."), ("Image type", "Shows that the image is real because actual routes meet."), ("Focus markers", "Shows the reference points used by the route rules.")]), reflection_prompts=["Why can a few selected routes still predict the real image?", "Why is the image from a Gather Lens a True Meeting Point rather than something stored inside the lens?"], mastery_skills=["lens_classification", "converging_parallel_ray", "central_ray_rule", "image_region_reasoning", "real_image_definition"], variation_plan={"diagnostic": "Fresh attempts rotate between route-rule recognition, F/2F anchor cases, and explanation stems about real-image formation.", "concept_gate": "Concept checks vary between selected-ray logic and image-region identification.", "mastery": "Mastery mixes 2F, beyond-2F, and between-F-and-2F cases with real-versus-ghost comparisons before repeating a stem."}, scaffold_support=scaffold("A converging lens forms a real image when selected refracted routes actually meet on the far side.", "Pick the most useful routes first: a parallel route and a center route often settle the image region quickly.", "What clue tells you the image is real in a converging-lens sketch?", "Do not treat every line on a sketch as a separate fact to memorize. The sketch is a route map built from a few reliable rules.", "The Gather Lens in the arena brings the routes together, making the True Meeting Point feel like a route result rather than a stored picture.", "Which selected route gives the strongest first clue about the far focus?", [extra_section("F and 2F anchors", "At 2F you get a same-size real image at 2F. Beyond 2F gives a smaller real image between F and 2F. Between F and 2F gives a larger real image beyond 2F.", "Which case gives the larger real image?"), extra_section("Route sketch economy", "A few carefully chosen routes are enough because all real routes from the same object point obey the same lens geometry.", "Why can two or three routes stand in for many?")]), visual_clarity_checks=visual_checks("converging-lens")))


def spread_lens_lesson() -> Dict[str, Any]:
    d = [
        mcq("M8L4_D1", "A Spread Lens is a...", ["diverging lens", "converging lens", "mirror", "prism"], 0, "Spread Lens means diverging lens.", ["lens_ray_rule_confusion"], skill_tags=["lens_classification"]),
        mcq("M8L4_D2", "A route parallel to the axis through a diverging lens emerges so that it...", ["appears to come from the near focus", "passes through the far focus", "reflects back", "stops"], 0, "Use the diverging parallel-ray rule.", ["lens_ray_rule_confusion"], skill_tags=["diverging_parallel_ray"]),
        short("M8L4_D3", "Why are dashed backward extensions used with a diverging lens?", ["Because they show where the spread routes appear to come from, even though no real light travels there.", "Because the extensions locate the ghost image position without claiming real light is there."], "Keep extensions separate from real routes.", ["ray_diagram_literal_confusion", "real_virtual_image_confusion"], skill_tags=["virtual_extension"], acceptance_rules=acceptance_groups(["extension", "backward", "dashed"], ["appear", "seem"], ["come from", "locate"], ["no real light", "not actual light"])),
        mcq("M8L4_D4", "The usual image from a diverging lens is...", ["virtual, upright, and smaller on the object side", "real, inverted, and larger on the far side", "same size at 2F", "no image"], 0, "That is the standard diverging-lens image.", ["real_virtual_image_confusion", "lens_ray_rule_confusion"], skill_tags=["diverging_image_properties"]),
        mcq("M8L4_D5", "In the thin-lens sketch, the center ray is treated as...", ["undeviated", "reflected", "always toward the near focus", "blocked"], 0, "The center ray stays the straight reference route.", ["lens_ray_rule_confusion"], skill_tags=["central_ray_rule"]),
        short("M8L4_D6", "Why is the diverging-lens image a Ghost Meeting Point?", ["Because the real routes spread and only the backward extensions appear to meet.", "Because the image is an apparent meeting point from dashed extensions, not a real crossing of light."], "Use spread-route and extension language.", ["real_virtual_image_confusion", "ray_diagram_literal_confusion"], skill_tags=["real_vs_virtual"], acceptance_rules=acceptance_groups(["spread", "diverge"], ["extension", "backward"], ["appear", "apparent"], ["meet", "cross"])),
        mcq("M8L4_D7", "The usual diverging-lens image lies...", ["between the lens and the near focus on the object side", "beyond 2F on the far side", "at the mirror surface", "behind the source only"], 0, "The virtual image sits between the lens and the near focus on the object side.", ["lens_ray_rule_confusion"], skill_tags=["diverging_image_region"]),
        mcq("M8L4_D8", "Which statement is weakest?", ["The dashed lines behind a diverging lens are actual beams", "The dashed lines show where the routes appear to come from", "The virtual image is upright", "The image is smaller than the object"], 0, "Extensions are not actual beams.", ["ray_diagram_literal_confusion"], skill_tags=["diagram_habits"]),
    ]
    c = [
        short("M8L4_C1", "How does the parallel-ray rule differ between Gather and Spread lenses?", ["A Gather Lens sends the parallel route through the far focus, but a Spread Lens makes it appear to come from the near focus.", "Converging lenses send parallel routes through the far focus, while diverging lenses make them appear to come from the near focus."], "Contrast actual crossing with apparent origin.", ["lens_ray_rule_confusion"], skill_tags=["lens_rule_contrast"], acceptance_rules=acceptance_groups(["gather", "converging"], ["far focus"], ["spread", "diverging"], ["appear", "seem"], ["near focus"])),
        mcq("M8L4_C2", "Why is the diverging-lens image virtual?", ["Because the real routes do not meet and only the backward extensions meet", "Because the lens is thin", "Because the source is dim", "Because the image is small"], 0, "Virtual images come from apparent intersections.", ["real_virtual_image_confusion", "ray_diagram_literal_confusion"], skill_tags=["real_vs_virtual"]),
        mcq("M8L4_C3", "Which route can still be treated as undeviated?", ["the center ray", "the parallel ray only", "the focus ray only", "no ray"], 0, "The center ray stays the standard straight route.", ["lens_ray_rule_confusion"], skill_tags=["central_ray_rule"]),
        short("M8L4_C4", "Why should dashed extensions behind a diverging lens not be called real routes?", ["Because no light actually travels backward there; the lines are only construction extensions.", "Because they are map extensions used to locate the apparent image, not real beams."], "Protect the difference between construction lines and actual light.", ["ray_diagram_literal_confusion"], skill_tags=["virtual_extension"], acceptance_rules=acceptance_groups(["no light", "no real light", "not actual light"], ["extension", "construction"], ["locate", "show"], ["apparent", "image"])),
        mcq("M8L4_C5", "Which description best fits the usual diverging-lens image?", ["upright and smaller on the object side", "inverted and larger on the far side", "same size at 2F", "real at the far focus"], 0, "That is the standard diverging-lens image description.", ["lens_ray_rule_confusion"], skill_tags=["diverging_image_properties"]),
        short("M8L4_C6", "Why can a diverging-lens route sketch still be trustworthy when it uses dashed extensions?", ["Because the extensions are valid geometry tools for predicting where the image appears, even though they are not real routes.", "Because the sketch is a map for image prediction, and dashed extensions mark the apparent origin consistently."], "A good route sketch can contain real paths and useful extensions.", ["ray_diagram_literal_confusion"], skill_tags=["ray_selection"], acceptance_rules=acceptance_groups(["extension", "dashed"], ["valid", "useful"], ["predict", "image"], ["appear", "apparent"])),
    ]
    t = [
        mcq("M8L4_M1", "A route parallel to the axis reaches a diverging lens. Draw it as...", ["spreading away as if it came from the near focus", "through the far focus", "straight back to the object", "along the lens surface"], 0, "Use the standard diverging rule.", ["lens_ray_rule_confusion"], skill_tags=["diverging_parallel_ray"]),
        short("M8L4_M2", "Describe the usual image from a diverging lens.", ["Virtual, upright, smaller, on the same side as the object.", "It forms a smaller upright ghost image between the lens and the near focus on the object side."], "Use the standard diverging-lens image properties together.", ["real_virtual_image_confusion"], skill_tags=["diverging_image_properties"], acceptance_rules=acceptance_groups(["virtual", "ghost"], ["upright"], ["smaller"], ["same side", "object side", "between the lens and the focus"])),
        mcq("M8L4_M3", "What clue tells you the image is not a True Meeting Point?", ["The real routes spread out and only the backward extensions meet", "The lens has curved surfaces", "The object is at 2F", "The axis is horizontal"], 0, "True images need actual crossings.", ["real_virtual_image_confusion"], skill_tags=["real_vs_virtual"]),
        mcq("M8L4_M4", "Which route still helps you construct a diverging-lens sketch quickly?", ["the center ray", "a reflected ray from the edge", "a ray along the surface only", "a route that ignores the axis"], 0, "The center ray is still useful.", ["lens_ray_rule_confusion"], skill_tags=["central_ray_rule"]),
        short("M8L4_M5", "Why is 'the dashed line is a real beam' incorrect?", ["Because the dashed line is only a backward extension used to locate the apparent image.", "Because no actual light travels there; the dashed line marks where the spread routes seem to come from."], "Keep the status of dashed lines explicit.", ["ray_diagram_literal_confusion"], skill_tags=["virtual_extension"], acceptance_rules=acceptance_groups(["dashed", "extension", "backward"], ["no actual light", "not real light", "no real light"], ["appear", "seem"], ["come from", "apparent image"])),
        mcq("M8L4_M6", "The usual diverging-lens image is located...", ["between the lens and the near focus", "beyond the far focus", "at 2F on the far side", "on the lens surface"], 0, "Use the standard region.", ["lens_ray_rule_confusion"], skill_tags=["diverging_image_region"]),
        mcq("M8L4_M7", "Which comparison is correct?", ["Gather lenses can make true meeting points, while Spread lenses usually make ghost meeting points", "Both lens types always make true meeting points", "Both lens types always make same-size images", "Spread lenses reflect instead of refract"], 0, "This captures the common difference between the two lens types.", ["real_virtual_image_confusion"], skill_tags=["lens_rule_contrast"]),
        short("M8L4_M8", "Why can a few selected routes still predict the ghost image for a diverging lens?", ["Because the selected routes and their backward extensions obey the same geometry as the full ray bundle.", "Because a small set of rule-based routes is enough to locate where the image appears even when the real rays spread out."], "The few-ray method still works for ghost images.", ["ray_diagram_literal_confusion"], skill_tags=["ray_selection"], acceptance_rules=acceptance_groups(["selected", "few", "key"], ["extension", "backward"], ["predict", "locate"], ["appear", "apparent", "ghost"])),
    ]
    return lesson_spec("M8_L4", "Spread Lenses and Ghost Meeting Points", sim("m8_ghost_finder_lab", "Ghost Finder lab", "Trace spread routes from a diverging lens and use dashed backward extensions to locate the ghost image.", ["Start with the parallel route and the center route.", "Watch the real routes spread on the far side.", "Use dashed extensions to locate the apparent image."], ["Apply diverging-lens route rules.", "Describe the usual virtual image.", "Use backward extensions without mistaking them for real routes."], ["object_distance_cm", "focal_length_cm", "virtual_image_offset_cm", "extension_toggle"], "Ghost-image route mapping."), d, "A Spread Lens makes the real Glow-Routes fan out, so the ghost image is found by backward extensions rather than by a real crossing.", "Before naming a Spread-Lens image, decide whether real routes meet or only the backward extensions meet.", [prompt_block("What does the parallel route do after a Spread Lens?", "It spreads as if it came from the near focus."), prompt_block("Why are the dashed lines not real beams?", "They are construction extensions for the apparent image.")], [prompt_block("Compare the real outgoing routes with their dashed extensions.", "Only the real routes exist on the far side."), prompt_block("Read where the image appears relative to the lens and the near focus.", "The image sits between the lens and the near focus on the object side.")], ["Explain why a Spread Lens forms a Ghost Meeting Point.", "Explain how the parallel-ray rule differs between converging and diverging lenses."], "Keep the status of real routes and dashed extensions visible before describing the diverging-lens image.", c, t, contract(concept_targets=["Use diverging-lens route rules to predict the usual virtual image.", "Distinguish between real routes and backward extensions.", "Compare converging-lens real images with diverging-lens ghost images."], core_concepts=["A diverging lens sends real routes outward so they appear to come from a focus on the object side.", "The usual diverging-lens image is virtual, upright, and smaller than the object.", "Backward extensions are construction lines, not real beams.", "A route sketch can still be valid even when some lines are extensions rather than actual light paths."], prerequisite_lessons=["M8_L3"], misconception_focus=["lens_ray_rule_confusion", "ray_diagram_literal_confusion", "real_virtual_image_confusion"], formulas=[relation("parallel in -> appears from near focus out; center ray -> straight through", "Diverging-lens route rules locate the usual ghost image by apparent backward origin.", ["diagram rules"], "Use in thin-lens ray diagrams.")], representations=[representation("words", "States the diverging-lens route rules and image properties."), representation("diagram", "Shows real spread routes and dashed backward extensions."), representation("formula", "Compresses the route rules.")], analogy_map=glow_route_map("the class is using spread routes and dashed extensions to locate a ghost image"), worked_examples=[worked("A parallel route reaches a diverging lens. What should the outgoing route do?", ["Draw the real route leaving the lens.", "Spread it away from the axis.", "Extend it backward to the near focus to mark the apparent origin."], "It emerges spreading outward as if it came from the near focus.", "That is the standard parallel-ray rule for a diverging lens.", "This anchors the key construction step for virtual images."), worked("Describe the usual image from a diverging lens.", ["Check whether the real routes meet.", "Notice that only the backward extensions meet on the object side.", "Read the image properties from that geometry."], "Virtual, upright, smaller, on the object side", "The image is virtual because only the backward extensions meet, and it is usually smaller and upright.", "This ties image properties to route behavior."), worked("A student points to the dashed extension and calls it a real beam. Correct it.", ["Ask whether any light actually travels backward there.", "Recognize the dashed line as a construction line.", "Use it only to locate the apparent image."], "The dashed line is not a real beam; it is a backward extension used to locate the ghost image.", "Route sketches use extensions as geometry tools, not as claims that light really travels there.", "This protects one of the module's most important diagram habits.")], visual_assets=[visual("m8-l4-spread-lens", "diverging_lens", "Spread Lens ghost image", "Shows real spread routes, dashed backward extensions, and the virtual image region.", "Real routes and dashed extensions must be visually separated.")], animation_assets=[animation("m8-l4-ghost-routes", "diverging_lens", "Ghost Finder", "Shows real routes spreading after the lens while dashed backward extensions mark the apparent image.")], simulation_contract=sim_contract("m8-l4-ghost-finder-lab", "diverging_lens", "Where do the real routes go after the Spread Lens, and where do the backward extensions appear to meet?", "Start with one object in front of a diverging lens and show both the real spread routes and their dashed backward extensions.", ["Toggle the dashed extensions on and off.", "Move the object and compare how the ghost image stays on the object side and remains smaller."], "Do not label dashed extensions as real light and keep the image virtual, upright, and smaller.", "A Spread Lens makes a ghost image because real routes spread while backward extensions show the apparent origin.", [("object_distance", "Object distance", "Changes the geometry of the apparent image."), ("focal_length", "Focal length", "Moves the near focus marker used by the parallel-ray rule."), ("extension_toggle", "Extension view", "Lets the learner separate real routes from dashed construction lines.")], [("Image type", "Shows that the image is virtual rather than real."), ("Image region", "Shows that the image stays between the lens and the near focus."), ("Route status", "Separates real outgoing routes from dashed extensions.")]), reflection_prompts=["Why is the usual image from a Spread Lens a Ghost Meeting Point?", "Why are dashed extensions still useful even though they are not real light paths?"], mastery_skills=["lens_classification", "diverging_parallel_ray", "diverging_image_properties", "diverging_image_region", "virtual_extension"], variation_plan={"diagnostic": "Fresh attempts rotate between parallel-ray rules, image-property descriptions, and dashed-extension interpretation.", "concept_gate": "Concept checks vary between comparing converging and diverging lenses and explaining the status of the ghost image.", "mastery": "Mastery mixes image-region reasoning, route-rule application, and extension-based explanation prompts before stems repeat."}, scaffold_support=scaffold("A diverging lens forms a ghost image because the real routes spread while their backward extensions appear to meet on the object side.", "Trace the real routes first. Then add dashed backward extensions only to mark the apparent origin and the image location.", "Do the real routes meet after the lens, or do only the backward extensions meet?", "Do not draw the dashed extension as if light truly travels there. It is a construction line, not a beam.", "The Spread Lens in the Glow-Route arena makes the image look like an apparent source point, which is why the lesson names it a Ghost Meeting Point.", "What single route clue tells you the image is virtual?", [extra_section("Near-focus clue", "For a diverging lens, a route parallel to the axis leaves as if it came from the near focus on the object side.", "Which focus belongs to the diverging parallel-ray rule?"), extra_section("Ghost image habit", "Virtual images still have definite positions in a route sketch, but they are found from extensions rather than from real route crossings.", "Why does an exact position not automatically make an image real?")]), visual_clarity_checks=visual_checks("diverging-lens")))


def tir_lesson() -> Dict[str, Any]:
    d = [
        mcq("M8L5_D1", "The Escape Edge is the...", ["critical angle", "focal length", "angle of reflection", "image height"], 0, "Escape Edge means critical angle.", ["critical_angle_confusion"], skill_tags=["critical_angle_definition"]),
        mcq("M8L5_D2", "At the critical angle the refracted route...", ["skims along the boundary", "reflects straight back", "goes through the far focus", "stops"], 0, "The refracted angle is 90 degrees to the normal.", ["critical_angle_confusion"], skill_tags=["critical_angle_geometry"]),
        short("M8L5_D3", "State the two conditions for Lock-Bounce total internal reflection.", ["Light must go from a slower higher-index medium to a faster lower-index medium, and the incident angle must be greater than the critical angle.", "TIR happens only when light tries to leave the slower medium for a faster one and the incident angle is above the critical angle."], "Both medium direction and angle matter.", ["critical_angle_confusion", "tir_direction_confusion"], skill_tags=["tir_conditions"], acceptance_rules=acceptance_groups(["slower", "higher-index"], ["faster", "lower-index"], ["greater than", "above"], ["critical angle"])),
        mcq("M8L5_D4", "Can total internal reflection happen from air into glass?", ["No", "Yes, if the angle is large enough", "Only at 2F", "Only if the surface is shiny"], 0, "TIR needs light to try to leave the slower medium.", ["tir_direction_confusion"], skill_tags=["direction_condition"]),
        mcq("M8L5_D5", "Critical angle 42 degrees, incident angle 50 degrees inside glass means...", ["Lock-Bounce total internal reflection", "refraction toward the normal", "a skim along the boundary", "no change"], 0, "Above the critical angle gives TIR.", ["critical_angle_confusion"], skill_tags=["tir_case_check"]),
        mcq("M8L5_D6", "If the incident angle equals the critical angle exactly, the route...", ["skims along the boundary", "fully total-internally reflects", "goes straight through undeviated", "becomes a plane-mirror image"], 0, "At the critical angle the refracted route is along the boundary.", ["critical_angle_confusion"], skill_tags=["critical_angle_geometry"]),
        short("M8L5_D7", "Why is it weak to treat the critical angle as just a number to memorize?", ["Because it marks the last possible escape route before total internal reflection begins.", "Because it is a boundary limit between escape and lock-bounce, not just a memorized value."], "Use limit-language.", ["critical_angle_confusion"], skill_tags=["limit_reasoning"], acceptance_rules=acceptance_groups(["last", "limit"], ["escape"], ["before", "between"], ["total internal reflection", "lock-bounce"])),
        mcq("M8L5_D8", "A strong application of repeated Lock-Bounce is...", ["optical fibers", "plane mirrors", "only prisms", "sound walls"], 0, "Fibers guide light by repeated TIR.", ["tir_direction_confusion"], skill_tags=["application_link"]),
    ]
    c = [
        short("M8L5_C1", "Why must light be trying to leave the slower medium before TIR can happen?", ["Because only then is there an escape attempt into a faster medium that can fail above the critical angle.", "Because Lock-Bounce needs the route to be going from the slower medium toward a faster one."], "The direction across the boundary matters.", ["tir_direction_confusion"], skill_tags=["direction_condition"], acceptance_rules=acceptance_groups(["leave", "escape"], ["slower", "higher-index"], ["faster", "lower-index"], ["critical angle"])),
        mcq("M8L5_C2", "What shows that the route has reached the critical angle?", ["The refracted route runs along the boundary", "The reflected angle becomes zero", "The image forms at 2F", "The mirror law takes over"], 0, "This is the defining geometry.", ["critical_angle_confusion"], skill_tags=["critical_angle_geometry"]),
        mcq("M8L5_C3", "If the incident angle is smaller than the critical angle, then...", ["some light still refracts out", "total internal reflection always occurs", "the route becomes virtual", "the route cannot meet the boundary"], 0, "Below the critical angle there is still escape.", ["critical_angle_confusion"], skill_tags=["escape_case_check"]),
        short("M8L5_C4", "Why is Lock-Bounce different from ordinary reflection at a mirror?", ["Because Lock-Bounce happens at a refracting boundary when the route cannot escape, not because it hit a mirror.", "Because total internal reflection is a failed escape from a slower medium rather than reflection from a shiny panel."], "Separate TIR from mirror reflection clearly.", ["tir_direction_confusion", "reflection_equal_angle_confusion"], skill_tags=["tir_vs_mirror"], acceptance_rules=acceptance_groups(["boundary", "interface"], ["cannot escape", "failed escape"], ["slower medium", "higher-index"], ["not", "rather than"], ["mirror"])),
        mcq("M8L5_C5", "Critical angle 40 degrees. Which incident angle gives a boundary-skimming refracted route?", ["40 degrees", "35 degrees", "45 degrees", "0 degrees"], 0, "The critical angle itself gives the skim case.", ["critical_angle_confusion"], skill_tags=["critical_angle_geometry"]),
        short("M8L5_C6", "Why are optical fibers a strong Lock-Bounce example?", ["Because the light keeps reflecting inside the core by repeated total internal reflection instead of escaping out.", "Because the route stays trapped in the light pipe by repeated failed escapes at the boundary."], "Use repeated failed-escape language.", ["tir_direction_confusion"], skill_tags=["application_link"], acceptance_rules=acceptance_groups(["repeated", "keeps"], ["total internal reflection", "lock-bounce", "failed escape"], ["inside", "core", "fiber", "light pipe"])),
    ]
    t = [
        mcq("M8L5_M1", "Critical angle 42 degrees, incident angle 38 degrees inside the slower medium means...", ["the route still refracts out", "Lock-Bounce total internal reflection", "a plane-mirror image", "the route stops"], 0, "Below the critical angle there is still escape.", ["critical_angle_confusion"], skill_tags=["escape_case_check"]),
        mcq("M8L5_M2", "Critical angle 42 degrees, incident angle 42 degrees means...", ["the refracted route runs along the boundary", "full TIR", "the route goes straight through undeviated", "the route becomes virtual"], 0, "At the critical angle the refracted route skims the boundary.", ["critical_angle_confusion"], skill_tags=["critical_angle_geometry"]),
        short("M8L5_M3", "Critical angle 42 degrees, incident angle 55 degrees inside glass. What happens and why?", ["Total internal reflection happens because the route is trying to leave glass for a faster medium and the angle is above the critical angle.", "Lock-Bounce occurs because the incident angle is greater than the critical angle while the light is leaving the slower medium."], "State both the medium direction and the angle condition.", ["critical_angle_confusion", "tir_direction_confusion"], skill_tags=["tir_case_check"], acceptance_rules=acceptance_groups(["total internal reflection", "lock-bounce"], ["greater than", "above"], ["critical angle"], ["leaving", "slower medium", "glass"], ["faster medium", "air"])),
        mcq("M8L5_M4", "Which situation cannot produce total internal reflection?", ["light going from air into glass", "light going from glass into air above the critical angle", "light in water trying to leave into air above the critical angle", "light in a fiber core above the critical angle"], 0, "Entering a slower medium cannot give TIR.", ["tir_direction_confusion"], skill_tags=["direction_condition"]),
        short("M8L5_M5", "Why is the Escape Edge called the last possible escape?", ["Because at that angle the refracted route is just able to skim along the boundary, and any larger angle prevents escape.", "Because it is the boundary limit between still escaping and being trapped by total internal reflection."], "Use boundary-limit language.", ["critical_angle_confusion"], skill_tags=["limit_reasoning"], acceptance_rules=acceptance_groups(["last", "limit"], ["escape"], ["boundary", "between"], ["greater", "larger", "above"], ["total internal reflection", "lock-bounce"])),
        mcq("M8L5_M6", "Why can a fiber guide light around bends?", ["Repeated total internal reflection keeps the light trapped in the core", "Plane mirrors are hidden inside the fiber", "The light becomes static", "The light stops refracting"], 0, "Fibers work by repeated TIR.", ["tir_direction_confusion"], skill_tags=["application_link"]),
        mcq("M8L5_M7", "Which pair fully describes the TIR condition?", ["from slower to faster medium, with incident angle above the critical angle", "from faster to slower medium, with any angle", "any medium pair if the source is bright enough", "only at mirrors"], 0, "Both the medium direction and the angle threshold are required.", ["tir_direction_confusion", "critical_angle_confusion"], skill_tags=["tir_conditions"]),
        short("M8L5_M8", "How is Lock-Bounce different from the mirror rule in Lesson 1?", ["Lock-Bounce is a failed escape at a refracting boundary, while the mirror rule describes reflection from a mirror surface.", "Total internal reflection happens because no refracted route can escape, not because the light hit a Bounce Panel."], "Separate mirror reflection from boundary-trapping reflection.", ["tir_direction_confusion", "reflection_equal_angle_confusion"], skill_tags=["tir_vs_mirror"], acceptance_rules=acceptance_groups(["failed escape", "cannot escape"], ["boundary", "refracting boundary", "interface"], ["mirror surface", "bounce panel"], ["not", "rather than"])),
    ]
    return lesson_spec("M8_L5", "Escape Edge and Lock-Bounce", sim("m8_escape_edge_lab", "Escape Edge lab", "Increase the incident angle inside a slow zone and compare escape, skim, and lock-bounce cases.", ["Start below the critical angle.", "Raise the incident angle until the route skims the boundary.", "Go beyond that angle and watch TIR take over."], ["Define the critical angle conceptually.", "State both TIR conditions.", "Explain optical fibers as repeated Lock-Bounce."], ["incident_angle_deg", "critical_angle_deg", "boundary_state", "lock_bounce_count"], "Critical-angle limit reasoning."), d, "Inside a slow zone, the Glow-Route can still escape until it reaches the Escape Edge; beyond that it lock-bounces back inside.", "Before deciding whether Lock-Bounce occurs, check both the boundary direction and the angle relative to the Escape Edge.", [prompt_block("What happens at the Escape Edge itself?", "The refracted route skims along the boundary."), prompt_block("Can Lock-Bounce happen from air into glass?", "No, because the route is entering the slower medium.")], [prompt_block("Raise the incident angle from below the critical angle to above it.", "Watch escape, skim, and lock-bounce."), prompt_block("Compare a mirror bounce with Lock-Bounce.", "One is a mirror surface; the other is a failed escape at a boundary.")], ["Explain why the critical angle is a boundary limit rather than just a memorized number.", "Explain why total internal reflection needs both a medium-direction condition and an angle condition."], "Keep the escape-limit idea visible before you treat the critical angle like a number to plug in.", c, t, contract(concept_targets=["Define the critical angle as the last possible escape angle.", "State the two conditions required for total internal reflection.", "Explain optical fibers as repeated failed escapes from a slower medium."], core_concepts=["The critical angle is the incident angle that makes the refracted route run along the boundary.", "Total internal reflection happens only when light tries to leave a slower higher-index medium for a faster lower-index medium.", "The incident angle must be greater than the critical angle for total internal reflection.", "Optical fibers guide light by repeated total internal reflection inside the core."], prerequisite_lessons=["M8_L2"], misconception_focus=["critical_angle_confusion", "tir_direction_confusion", "reflection_equal_angle_confusion"], formulas=[relation("incident angle = critical angle -> refracted angle = 90 degrees", "The critical angle is the boundary limit between escape and total internal reflection.", ["degrees"], "Use when light is trying to leave the slower medium.")], representations=[representation("words", "Explains the critical-angle limit and the two TIR conditions."), representation("diagram", "Shows escape, skim, and lock-bounce cases at one boundary."), representation("formula", "States the 90-degree boundary condition at the critical angle.")], analogy_map=glow_route_map("the class is comparing escape, skim, and lock-bounce behavior at a boundary"), worked_examples=[worked("Critical angle 42 degrees, incident angle 38 degrees. What happens?", ["Compare the incident angle with the critical angle.", "Notice that the route is still below the limit.", "State the boundary outcome."], "The route still refracts out.", "Below the critical angle, there is still an escaping refracted route.", "This gives the below-limit case a clear anchor."), worked("Critical angle 42 degrees, incident angle 42 degrees. What happens?", ["Compare the incident angle with the critical angle.", "Recognize the exact limit case.", "Describe the refracted route geometry."], "The refracted route skims along the boundary.", "At the critical angle, the refracted angle is 90 degrees to the normal.", "This makes the limit meaning concrete."), worked("Critical angle 42 degrees, incident angle 55 degrees inside glass. What happens?", ["Check that the light is trying to leave the slower medium.", "Compare the angle with the critical angle.", "State the full boundary result."], "Total internal reflection occurs.", "Above the critical angle, no refracted route can escape, so the route reflects back inside.", "This secures the full TIR condition set.")], visual_assets=[visual("m8-l5-lock-bounce", "total_internal_reflection", "Escape edge and lock-bounce", "Shows the below-limit escape case, the skim case, and the total internal reflection case.", "The three boundary states should stay visually distinct.")], animation_assets=[animation("m8-l5-escape-limit", "total_internal_reflection", "Escape limit", "Shows the refracted route approaching the boundary, skimming it, and then disappearing into total internal reflection.")], simulation_contract=sim_contract("m8-l5-escape-edge-lab", "total_internal_reflection", "Is the route trying to leave the slower medium, and where is the incident angle relative to the Escape Edge?", "Start with a route inside the slower medium and increase the incident angle from below the critical angle upward.", ["Compare the below-critical, equal-critical, and above-critical cases.", "Switch the direction so the route goes from the faster medium into the slower one and check that lock-bounce is no longer possible."], "Do not apply TIR in the wrong direction or treat the critical angle as a number without its boundary-limit meaning.", "The Escape Edge is the last possible escape, and Lock-Bounce occurs only for the correct boundary direction above that limit.", [("incident_angle", "Incident angle", "Moves the route from escape to skim to lock-bounce."), ("critical_angle", "Critical angle", "Shows the threshold value for the current boundary."), ("boundary_direction", "Boundary direction", "Checks whether the route is leaving the slower medium or entering it.")], [("Boundary state", "Shows escape, skim, or lock-bounce for the current case."), ("Critical-angle comparison", "Shows whether the incident angle is below, equal to, or above the critical angle."), ("Lock-bounce count", "Shows repeated reflections in the light-pipe style case.")]), reflection_prompts=["Why is the critical angle better understood as a boundary limit than as a number to memorize?", "Why must total internal reflection involve light trying to leave the slower medium rather than entering it?"], mastery_skills=["critical_angle_definition", "critical_angle_geometry", "tir_conditions", "direction_condition", "application_link"], variation_plan={"diagnostic": "Fresh attempts rotate between condition checks, critical-angle geometry, and application prompts.", "concept_gate": "Concept checks vary between explaining the limit idea, checking the boundary direction, and comparing below/equal/above-critical cases.", "mastery": "Mastery mixes numerical critical-angle comparisons, TIR condition summaries, and optical-fiber explanations before repeats are chosen."}, scaffold_support=scaffold("The critical angle is the last angle that still allows escape from the slower medium.", "Check the boundary direction first, then compare the incident angle with the critical angle to decide whether the route escapes, skims, or lock-bounces.", "If the route is below the critical angle, should some light still escape?", "Do not use total internal reflection in the wrong direction across the boundary.", "The Escape Edge in the Glow-Route arena turns the critical angle into a visible boundary limit rather than a bare number.", "What has to be true before Lock-Bounce is even possible?", [extra_section("Three boundary states", "Below the critical angle the route escapes, at the critical angle it skims the boundary, and above it the route lock-bounces back inside.", "Which state belongs to the exact critical angle?"), extra_section("Fiber clue", "A light pipe works because the route keeps meeting the boundary above the critical angle while trying to stay inside the slower core.", "Why does the light stay trapped in the fiber core?")]), visual_clarity_checks=visual_checks("critical-angle")))


def route_sketch_lesson() -> Dict[str, Any]:
    d = [
        mcq("M8L6_D1", "A Route Sketch is a...", ["ray diagram", "diffraction pattern", "filter", "circuit diagram"], 0, "Route Sketch means ray diagram.", ["ray_diagram_literal_confusion"], skill_tags=["diagram_purpose"]),
        mcq("M8L6_D2", "Why are only a few routes usually drawn?", ["A few selected routes are enough to predict the image position", "Only a few rays exist", "The lens blocks the rest", "Dashed lines are forbidden"], 0, "A ray diagram is a selected-route prediction tool.", ["ray_diagram_literal_confusion"], skill_tags=["ray_selection"]),
        short("M8L6_D3", "What is the difference between a True Meeting Point and a Ghost Meeting Point?", ["A True Meeting Point is where real routes actually meet, while a Ghost Meeting Point is where routes only appear to meet by extension.", "A real image comes from actual ray crossings, but a virtual image comes from apparent intersections of backward extensions."], "Keep actual crossings separate from apparent ones.", ["real_virtual_image_confusion"], skill_tags=["real_vs_virtual"], acceptance_rules=acceptance_groups(["true", "real"], ["actual"], ["routes", "rays"], ["meet", "cross"], ["ghost", "virtual", "extension", "appear"])),
        mcq("M8L6_D4", "In a plane-mirror sketch, which lines behind the mirror are real?", ["None of them", "All of them", "Only the brightest", "Only the Guide Line"], 0, "Mirror-image lines behind the mirror are construction extensions.", ["ray_diagram_literal_confusion"], skill_tags=["extension_status"]),
        mcq("M8L6_D5", "Object 7 cm in front of a plane mirror. Image?", ["7 cm behind", "14 cm behind", "at 2F", "at the lens center"], 0, "Plane-mirror images sit the same distance behind the mirror.", ["mirror_image_surface_confusion"], skill_tags=["mirror_geometry"]),
        short("M8L6_D6", "Why can a ray diagram still be trustworthy even when some lines are dashed extensions?", ["Because the dashed lines are valid geometry tools for locating apparent images, even though they are not real light paths.", "Because the sketch is a prediction map, so extensions can mark where light seems to come from without claiming real light is there."], "A route sketch can mix real routes and useful extensions.", ["ray_diagram_literal_confusion"], skill_tags=["diagram_purpose"], acceptance_rules=acceptance_groups(["dashed", "extension"], ["valid", "useful"], ["locate", "show"], ["apparent", "seem"], ["not real", "not actual"])),
        mcq("M8L6_D7", "Which statement best fits a real image from a converging lens?", ["The actual refracted routes meet on the far side", "Only the dashed extensions meet on the object side", "It must always be behind a mirror", "No screen could ever be placed there"], 0, "Real images come from actual route crossings.", ["real_virtual_image_confusion"], skill_tags=["real_image_use"]),
        mcq("M8L6_D8", "Which line is usually only a reference, not a light route?", ["the Guide Line", "the incident route", "the reflected route", "the refracted route"], 0, "The Guide Line is a reference line, not a beam.", ["normal_reference_confusion", "ray_diagram_literal_confusion"], skill_tags=["diagram_roles"]),
    ]
    c = [
        short("M8L6_C1", "Why does a route sketch use only a few carefully chosen routes instead of every possible one?", ["Because a few rule-based routes are enough to predict the image position and type.", "Because the selected rays give the same image prediction as the full ray bundle while keeping the sketch readable."], "Route sketches are efficient geometry maps.", ["ray_diagram_literal_confusion"], skill_tags=["ray_selection"], acceptance_rules=acceptance_groups(["few", "selected"], ["predict", "image"], ["same", "full bundle"], ["readable", "efficient"])),
        mcq("M8L6_C2", "Dashed lines behind a diverging lens are...", ["backward extensions showing where the routes appear to come from", "real beams traveling backward", "Guide Lines only", "mirror surfaces"], 0, "They are apparent-origin extensions.", ["ray_diagram_literal_confusion"], skill_tags=["extension_status"]),
        mcq("M8L6_C3", "What makes a plane-mirror image and a diverging-lens image similar in a sketch?", ["Both are ghost meeting points located by backward extensions", "Both are true meeting points", "Both use total internal reflection", "Both require a screen"], 0, "Both are virtual images found by extensions.", ["real_virtual_image_confusion"], skill_tags=["virtual_image_comparison"]),
        short("M8L6_C4", "Why is 'every line in the diagram is a real beam' weak?", ["Because some lines are reference lines or backward extensions used only for geometry, not actual light paths.", "Because ray diagrams include Guide Lines and dashed construction lines in addition to real routes."], "Separate real routes, reference lines, and extensions.", ["ray_diagram_literal_confusion", "normal_reference_confusion"], skill_tags=["diagram_roles"], acceptance_rules=acceptance_groups(["reference", "guide line", "normal"], ["extension", "construction", "dashed"], ["not real", "not actual"])),
        mcq("M8L6_C5", "Object 5 cm in front of a plane mirror means object-image separation...", ["10 cm", "5 cm", "2.5 cm", "15 cm"], 0, "The image is 5 cm behind the mirror, so the separation is 10 cm.", ["mirror_image_surface_confusion"], skill_tags=["mirror_geometry"]),
        short("M8L6_C6", "Why could a screen capture the image from a converging lens but not the image behind a plane mirror?", ["Because the converging-lens image is a true meeting point of real routes, while the mirror image is only an apparent position from extensions.", "Because a screen can catch real rays where they actually meet, but it cannot catch a ghost image formed only by apparent backward paths."], "Use screenability as evidence for real versus ghost images.", ["real_virtual_image_confusion"], skill_tags=["real_image_use"], acceptance_rules=acceptance_groups(["screen", "capture"], ["real", "actual"], ["routes", "rays"], ["meet", "cross"], ["apparent", "mirror", "ghost", "extension"])),
    ]
    t = [
        mcq("M8L6_M1", "Which pair of statements is strongest?", ["A route sketch is a prediction map, and dashed extensions can still be valid parts of it", "Every line drawn is a literal beam", "The Guide Line is a real ray", "Virtual images are not worth drawing"], 0, "Good route sketches mix real paths and useful construction lines deliberately.", ["ray_diagram_literal_confusion"], skill_tags=["diagram_purpose"]),
        short("M8L6_M2", "A plane mirror has an object 9 cm in front of it. Where is the image and why?", ["9 cm behind the mirror, because the mirror geometry makes the ghost image the same distance behind as the object is in front.", "The image is 9 cm behind the mirror because the backward extensions are symmetric about the mirror surface."], "Use symmetric plane-mirror geometry.", ["mirror_image_surface_confusion"], skill_tags=["mirror_geometry"], acceptance_rules=acceptance_groups(["9 cm", "9"], ["behind the mirror", "behind"], ["same distance", "symmetric"], ["in front", "object"])),
        mcq("M8L6_M3", "Which image could be caught on a screen?", ["the true meeting point from a converging lens", "the ghost image behind a plane mirror", "the ghost image from a diverging lens", "the backward extension itself"], 0, "Only real images can be caught on a screen.", ["real_virtual_image_confusion"], skill_tags=["real_image_use"]),
        mcq("M8L6_M4", "Which line should never be mistaken for a light path?", ["the Guide Line", "the actual refracted route", "the actual reflected route", "the actual route through the lens"], 0, "The Guide Line is a reference, not a beam.", ["normal_reference_confusion", "ray_diagram_literal_confusion"], skill_tags=["diagram_roles"]),
        short("M8L6_M5", "Why is a diverging-lens image drawn with backward extensions on the object side?", ["Because the real routes spread out, so the ghost image is found where their backward extensions appear to meet.", "Because the image is virtual and only the apparent backward paths locate it on the object side."], "Use spread-route plus extension language.", ["ray_diagram_literal_confusion"], skill_tags=["virtual_image_comparison"], acceptance_rules=acceptance_groups(["spread", "diverge"], ["extension", "backward"], ["appear", "seem"], ["meet", "locate"], ["virtual", "ghost"])),
        mcq("M8L6_M6", "A converging lens forms an image where actual routes cross. That label is...", ["True Meeting Point", "Ghost Meeting Point", "Guide Line", "Escape Edge"], 0, "Actual route crossing means real image.", ["real_virtual_image_confusion"], skill_tags=["real_vs_virtual"]),
        mcq("M8L6_M7", "Why can the same unit use both real routes and dashed extensions?", ["Because route sketches are reasoning tools that can include both actual paths and construction lines", "Because light changes type halfway through", "Because the normal becomes a real route", "Because optics diagrams do not need rules"], 0, "A route sketch is a mixed geometry map when used carefully.", ["ray_diagram_literal_confusion"], skill_tags=["diagram_purpose"]),
        short("M8L6_M8", "What three kinds of lines might appear in one optics sketch, and why should they be kept separate?", ["Real routes, Guide Lines, and dashed extensions should be kept separate because they play different roles in the reasoning.", "Actual rays, reference normals, and construction extensions are different line types and should not all be treated as literal light paths."], "Strong optics reading depends on knowing what each line is doing.", ["ray_diagram_literal_confusion", "normal_reference_confusion"], skill_tags=["diagram_roles"], acceptance_rules=acceptance_groups(["real routes", "actual rays"], ["guide line", "normal", "reference"], ["extension", "dashed", "construction"], ["different", "separate"], ["roles", "reasoning"])),
    ]
    return lesson_spec("M8_L6", "Route Sketches, Real Images, and Ghost Images", sim("m8_route_sketch_lab", "Route Sketch lab", "Switch between a real-image sketch and a ghost-image sketch to separate actual routes, Guide Lines, and dashed extensions.", ["Begin with a converging-lens real image.", "Switch to a mirror or diverging-lens ghost image.", "Keep labeling which lines are real routes, references, and extensions."], ["Use ray diagrams as deliberate prediction tools.", "Distinguish true meeting points from ghost meeting points.", "Keep reference lines and extensions from being mistaken for real light paths."], ["sketch_mode", "object_distance_cm", "image_type", "line_status_labels"], "Route-sketch interpretation."), d, "The Route Sketch Board uses a small number of carefully chosen routes, Guide Lines, and sometimes dashed backward extensions to predict where light really meets or only appears to meet.", "Before trusting any optics sketch, decide what each line type represents: a real route, a Guide Line, or a backward extension.", [prompt_block("What kind of line is the Guide Line in a route sketch?", "A reference line, not a light route."), prompt_block("What makes a Ghost Meeting Point different from a True Meeting Point?", "Ghost points are found by extensions; true points are real crossings.")], [prompt_block("Compare a converging-lens real image with a plane-mirror or diverging-lens ghost image.", "Ask where actual routes meet and where only extensions meet."), prompt_block("Read one sketch while naming the status of every line you point to.", "Reference, real route, or backward extension are not the same thing.")], ["Explain why a route sketch is a smart map rather than a literal picture of every beam.", "Explain how the same optics unit can use both true image points and ghost image points without contradiction.", "Explain how the screen test separates a True Meeting Point from a Ghost Meeting Point."], "Keep the purpose of each line visible before you judge the image type or position in a route sketch.", c, t, contract(concept_targets=["Use ray diagrams as prediction tools rather than literal copies of every beam.", "Distinguish true meeting points from ghost meeting points across mirrors and lenses.", "Keep real routes, Guide Lines, and dashed extensions separate while reasoning from a sketch."], core_concepts=["A ray diagram uses a few selected routes because they are enough to predict image position and type.", "A real image is a true meeting point of actual routes and can be captured on a screen.", "A virtual image is a ghost meeting point found by backward extensions rather than by actual route crossings.", "Guide Lines and dashed extensions are not themselves light paths and must be read differently from real routes."], prerequisite_lessons=["M8_L1", "M8_L3", "M8_L4"], misconception_focus=["ray_diagram_literal_confusion", "real_virtual_image_confusion", "mirror_image_surface_confusion", "normal_reference_confusion"], formulas=[relation("route sketch = selected real routes + references + optional backward extensions", "A ray diagram is a geometry map for image prediction, not a claim that every drawn line is an actual beam.", ["diagram rules"], "Use when interpreting mirrors and lenses.")], representations=[representation("words", "Explains what each line type does in a route sketch."), representation("diagram", "Contrasts real-image and ghost-image sketches."), representation("formula", "Compresses the route-sketch reading rule.")], analogy_map=glow_route_map("the class is using route sketches to separate real crossings from apparent ones"), worked_examples=[worked("Object 7 cm in front of a plane mirror. Where is the image?", ["Use plane-mirror symmetry.", "Place the ghost image the same distance behind the mirror.", "Remember that lines behind the mirror are backward extensions."], "7 cm behind the mirror", "Plane-mirror images are virtual positions located by symmetric backward extensions.", "This keeps the classic mirror case alive in the capstone lesson."), worked("A converging lens forms an image where actual routes cross on the far side. What type of image is it?", ["Ask whether the actual routes really meet.", "Notice that the crossing is real and on the far side.", "Read the image type from that crossing."], "A real image at a True Meeting Point", "Actual route crossings define real images and could be captured on a screen.", "This links ray diagrams to a physical test for reality."), worked("A diverging-lens sketch shows dashed lines meeting on the object side. What should you say?", ["Check whether the real routes meet anywhere.", "Notice that only the backward extensions meet.", "Read the image type from that apparent intersection."], "A virtual image at a Ghost Meeting Point", "Only apparent backward intersections make virtual images; no real routes meet there.", "This contrasts cleanly with the converging-lens case.")], visual_assets=[visual("m8-l6-route-sketch", "ray_diagram", "Route Sketch line roles", "Shows a real-image sketch beside a ghost-image sketch with labels on real routes, Guide Lines, and dashed extensions.", "Optics sketches become more trustworthy when each line type has a clear role.")], animation_assets=[animation("m8-l6-sketch-toggle", "ray_diagram", "Sketch toggle", "Shows the board switching between a real-image case and a ghost-image case while highlighting the status of each line type.")], simulation_contract=sim_contract("m8-l6-route-sketch-lab", "ray_diagram", "Which lines are real routes, which are Guide Lines, and where do the true or ghost meeting points appear?", "Start with a converging-lens real-image sketch and label the actual crossing first, then compare it with a ghost-image sketch.", ["Switch between a real-image case and a ghost-image case while keeping the line-status labels visible.", "Compare a plane-mirror ghost image with a diverging-lens ghost image so the learner sees the shared role of backward extensions."], "Do not treat every line as an actual beam and use screenability as evidence for a true meeting point.", "Ray diagrams are smart maps that mix selected routes, references, and backward extensions to predict real and virtual images.", [("sketch_mode", "Sketch mode", "Switches between real-image and ghost-image cases."), ("object_distance", "Object distance", "Changes the geometry while the line roles stay distinct."), ("line_labels", "Line-status labels", "Helps the learner separate real routes, Guide Lines, and dashed extensions.")], [("Image type", "Shows whether the current case is a true or ghost meeting point."), ("Line roles", "Lists which lines are real routes, references, or extensions."), ("Image position", "Shows the predicted location from the selected sketch.")]), reflection_prompts=["Why is a route sketch a smart map rather than a literal picture where every line is a real beam?", "How can the same optics unit legitimately use both True Meeting Points and Ghost Meeting Points?", "Why does the screen test separate a True Meeting Point from a Ghost Meeting Point?"], mastery_skills=["diagram_purpose", "ray_selection", "real_vs_virtual", "extension_status", "diagram_roles"], variation_plan={"diagnostic": "Fresh attempts rotate between line-status questions, mirror geometry, and real-versus-ghost image prompts.", "concept_gate": "Concept checks vary between sketch-purpose explanation, screenability reasoning, and line-role identification.", "mastery": "Mastery mixes mirror cases, converging-lens real-image cases, and diverging-lens ghost-image cases before repeated route-sketch stems are preferred."}, scaffold_support=scaffold("A route sketch is a prediction map that mixes selected real routes, reference lines, and sometimes backward extensions.", "Name the status of each line before you infer the image. That habit prevents the biggest optics misunderstanding in this module.", "If only the backward extensions meet, what image type should you name?", "Do not collapse Guide Lines, real routes, and dashed extensions into one category just because they are all drawn with lines.", "The Route Sketch Board in the Glow-Route arena makes line roles explicit so learners can move from mirrors to lenses without losing track of what each line means.", "What changes first when you switch from a True Meeting Point sketch to a Ghost Meeting Point sketch?", [extra_section("Screen test", "A screen can capture a real image because actual routes meet there. A virtual image cannot be captured there because only apparent extensions meet.", "Why does a screen test distinguish true and ghost meeting points?"), extra_section("Three line roles", "Real routes show actual light travel, Guide Lines set the reference for angles, and dashed extensions show apparent origins or image positions.", "Which one of these three is not a light path at all?")]), visual_clarity_checks=visual_checks("route-sketch")))


M8_SPEC = {
    "authoring_standard": AUTHORING_STANDARD_V3,
    "module_description": "Reflection in mirrors, refraction in lenses, critical angle, total internal reflection, and ray diagrams taught through the Glow-Route model of light.",
    "mastery_outcomes": [
        "Explain mirror reflection using equal angles measured from the normal.",
        "Explain refraction as a speed-change effect across a boundary and predict bending toward or away from the normal.",
        "Use standard converging-lens ray rules to predict real image position and type.",
        "Use standard diverging-lens ray rules to predict virtual image position and type.",
        "Define the critical angle conceptually and explain total internal reflection as a failed escape from a slower medium.",
        "Use ray diagrams as route maps that distinguish real routes, Guide Lines, and backward extensions.",
    ],
    "lessons": [mirror_lesson(), refraction_lesson(), gather_lens_lesson(), spread_lens_lesson(), tir_lesson(), route_sketch_lesson()],
}


RELEASE_CHECKS = [
    "Every lesson ties its optics angles to the Guide Line normal rather than to the surface.",
    "Every lesson uses the Glow-Route analogy to support the formal optics rules rather than replace them with slogans.",
    "Every explorer is backed by a lesson-specific simulation contract rather than generic fallback wording.",
    "Every lesson-owned assessment bank is broad enough to prefer unseen questions on fresh attempts before repeated stems.",
    "Every route-sketch lesson keeps dashed extensions visibly separate from real routes and reference lines.",
    "Every worked example explains why the answer follows rather than naming only the label or rule.",
]


M8_MODULE_DOC, M8_LESSONS, M8_SIM_LABS = build_nextgen_module_bundle(
    module_id=M8_MODULE_ID,
    module_title=M8_MODULE_TITLE,
    module_spec=M8_SPEC,
    allowlist=M8_ALLOWLIST,
    content_version=M8_CONTENT_VERSION,
    release_checks=RELEASE_CHECKS,
    sequence=12,
    level="Module 8",
    estimated_minutes=300,
    authoring_standard=AUTHORING_STANDARD_V3,
    plan_assets=True,
    public_base="/lesson_assets",
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed Module M8 into Firestore")
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

    module_doc = deepcopy(M8_MODULE_DOC)
    lesson_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in M8_LESSONS]
    sim_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in M8_SIM_LABS]

    if args.compile_assets:
        render_module_assets(lesson_pairs, sim_pairs, asset_root=asset_root, public_base=args.public_base)

    print_preview(module_doc, lesson_pairs, sim_pairs)
    db = init_firebase(project)
    plan: List[Tuple[str, str]] = [("modules", M8_MODULE_ID)]
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
