from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List, Sequence, Tuple

try:
    from scripts.lesson_authoring_contract import (
        AUTHORING_STANDARD_V1,
        AUTHORING_STANDARD_V2,
        default_assessment_alignment,
        default_competency_mapping,
        default_question_assessment_schema,
        default_spiral_reinforcement,
        validate_nextgen_module,
    )
    from scripts.module_asset_pipeline import DEFAULT_PUBLIC_BASE, plan_module_assets
    from scripts.nextgen_module_scaffold import build_nextgen_module_scaffold
except ModuleNotFoundError:
    from lesson_authoring_contract import (
        AUTHORING_STANDARD_V1,
        AUTHORING_STANDARD_V2,
        default_assessment_alignment,
        default_competency_mapping,
        default_question_assessment_schema,
        default_spiral_reinforcement,
        validate_nextgen_module,
    )
    from module_asset_pipeline import DEFAULT_PUBLIC_BASE, plan_module_assets
    from nextgen_module_scaffold import build_nextgen_module_scaffold

try:
    from scripts.seed_m1_module import utc_now
except ModuleNotFoundError:
    from seed_m1_module import utc_now


def _safe_tags(tags: Sequence[str], allowlist: Sequence[str]) -> List[str]:
    allowed = set(str(tag) for tag in allowlist)
    return [str(tag) for tag in tags if str(tag) in allowed]


def _question(spec: Dict[str, Any], allowlist: Sequence[str], phase_key: str = "") -> Dict[str, Any]:
    hint = str(spec["hint"])
    tags = _safe_tags(list(spec.get("tags") or spec.get("misconception_tags") or []), allowlist)
    acceptance_rules = deepcopy(dict(spec.get("acceptance_rules") or {}))
    skill_tags = [str(tag) for tag in spec.get("skill_tags") or [] if str(tag).strip()]
    qtype = str(spec.get("kind") or spec.get("type") or "").strip().lower()
    assessment_schema = default_question_assessment_schema(
        qtype,
        phase_key=phase_key,
        raw_schema=deepcopy(dict(spec.get("assessment_schema") or {})),
    )
    if qtype == "mcq":
        choices = list(spec["choices"])
        question = {
            "id": str(spec["id"]),
            "question_id": str(spec["id"]),
            "type": "mcq",
            "prompt": str(spec["prompt"]),
            "choices": choices,
            "answer_index": int(spec["answer_index"]),
            "hint": hint,
            "feedback": [hint for _ in choices],
            "misconception_tags": tags,
            "assessment_schema": assessment_schema,
        }
        if skill_tags:
            question["skill_tags"] = skill_tags
        return question
    question = {
        "id": str(spec["id"]),
        "question_id": str(spec["id"]),
        "type": "short",
        "prompt": str(spec["prompt"]),
        "accepted_answers": list(spec["accepted_answers"]),
        "hint": hint,
        "feedback": [hint],
        "misconception_tags": tags,
        "assessment_schema": assessment_schema,
    }
    if acceptance_rules:
        question["acceptance_rules"] = acceptance_rules
    if skill_tags:
        question["skill_tags"] = skill_tags
    return question


def _prompt_blocks(items: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        {"prompt": str(item["prompt"]), "hint": str(item["hint"])}
        for item in items
    ]


def _cloned_items(items: Sequence[Any]) -> List[Any]:
    return [deepcopy(item) for item in items]


def build_nextgen_module_bundle(
    *,
    module_id: str,
    module_title: str,
    module_spec: Dict[str, Any],
    allowlist: Sequence[str],
    content_version: str,
    release_checks: Sequence[str],
    sequence: int,
    level: str,
    estimated_minutes: int,
    authoring_standard: str | None = None,
    plan_assets: bool = False,
    public_base: str = DEFAULT_PUBLIC_BASE,
) -> Tuple[Dict[str, Any], List[Tuple[str, Dict[str, Any]]], List[Tuple[str, Dict[str, Any]]]]:
    resolved_authoring_standard = str(
        authoring_standard or module_spec.get("authoring_standard") or AUTHORING_STANDARD_V1
    )
    module_doc, lessons, sim_labs = build_nextgen_module_scaffold(
        module_id,
        module_title,
        str(module_spec["module_description"]),
        [str(lesson["title"]) for lesson in module_spec["lessons"]],
        allowlist,
        sequence=sequence,
        level=level,
        estimated_minutes=estimated_minutes,
    )
    module_doc.update(
        {
            "content_version": content_version,
            "mastery_outcomes": list(module_spec["mastery_outcomes"]),
            "misconception_tag_allowlist": list(allowlist),
            "authoring_standard": resolved_authoring_standard,
            "updated_utc": utc_now(),
        }
    )

    lesson_by_id = {str(lesson["lesson_id"]): lesson for lesson in lessons}
    sim_by_lesson = {str(lesson["lesson_id"]): sim for lesson, sim in zip(lessons, sim_labs)}

    for lesson_spec in module_spec["lessons"]:
        lesson = lesson_by_id[str(lesson_spec["id"])]
        sim = sim_by_lesson[str(lesson_spec["id"])]
        lesson["updated_utc"] = utc_now()
        sim_spec = dict(lesson_spec["sim"])
        lesson["phases"]["simulation_inquiry"]["lab_id"] = str(sim_spec["lab_id"])
        sim.update(
            {
                "lab_id": str(sim_spec["lab_id"]),
                "module_id": module_id,
                "title": str(sim_spec["title"]),
                "description": str(sim_spec["description"]),
                "instructions": list(sim_spec["instructions"]),
                "expected_outcomes": list(sim_spec["outcomes"]),
                "telemetry_schema_hint": {
                    "fields": list(sim_spec["fields"]),
                    "sim_depth_meaning": str(sim_spec["depth"]),
                },
                "updated_utc": utc_now(),
            }
        )
        lesson["phases"]["diagnostic"] = {
            "two_tier": True,
            "items": [_question(item, allowlist, "diagnostic") for item in lesson_spec["diagnostic"]],
            "notes": str(
                lesson_spec.get("diagnostic_notes")
                or "Use the opening check to surface the main misconception before the lesson deepens it."
            ),
        }
        lesson["phases"]["analogical_grounding"] = {
            "analogy_text": str(lesson_spec["analogy_text"]),
            "commitment_prompt": str(lesson_spec["commitment_prompt"]),
            "micro_prompts": _prompt_blocks(list(lesson_spec["micro_prompts"])),
        }
        lesson["phases"]["simulation_inquiry"]["inquiry_prompts"] = _prompt_blocks(list(lesson_spec["inquiry"]))
        lesson["phases"]["concept_reconstruction"] = {
            "prompts": list(lesson_spec["recon_prompts"]),
            "capsules": [
                {
                    "prompt": str(lesson_spec["capsule_prompt"]),
                    "checks": [_question(item, allowlist, "concept_reconstruction") for item in lesson_spec["capsule_checks"]],
                }
            ],
        }
        lesson["phases"]["transfer"] = {
            "items": [_question(item, allowlist, "transfer") for item in lesson_spec["transfer"]],
            "notes": str(
                lesson_spec.get("transfer_notes")
                or "Use transfer to check whether the idea survives a fresh context or representation."
            ),
        }

        contract = deepcopy(dict(lesson_spec["contract"]))
        contract["misconception_focus"] = _safe_tags(list(contract["misconception_focus"]), allowlist)
        contract["formulas"] = _cloned_items(list(contract["formulas"]))
        contract["representations"] = _cloned_items(list(contract["representations"]))
        contract["worked_examples"] = _cloned_items(list(contract["worked_examples"]))
        contract["visual_assets"] = _cloned_items(list(contract.get("visual_assets") or []))
        contract["animation_assets"] = _cloned_items(list(contract.get("animation_assets") or []))
        contract["release_checks"] = list(release_checks)
        contract["assessment_alignment"] = deepcopy(contract.get("assessment_alignment") or default_assessment_alignment())
        contract["competency_mapping"] = deepcopy(contract.get("competency_mapping") or default_competency_mapping())
        contract["spiral_reinforcement"] = deepcopy(contract.get("spiral_reinforcement") or default_spiral_reinforcement())
        lesson["authoring_contract"] = contract

    lesson_pairs: List[Tuple[str, Dict[str, Any]]] = [(str(lesson["lesson_id"]), lesson) for lesson in lessons]
    sim_pairs: List[Tuple[str, Dict[str, Any]]] = [(str(sim["lab_id"]), sim) for sim in sim_labs]

    validate_nextgen_module(
        module_doc,
        [payload for _, payload in lesson_pairs],
        [payload for _, payload in sim_pairs],
        allowlist,
    )

    if plan_assets:
        plan_module_assets(lesson_pairs, sim_pairs, public_base=public_base)

    return module_doc, lesson_pairs, sim_pairs
