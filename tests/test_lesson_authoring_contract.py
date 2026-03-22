from __future__ import annotations

import unittest
from copy import deepcopy

from scripts.lesson_authoring_contract import (
    AUTHORING_STANDARD_V3,
    default_assessment_alignment,
    default_competency_mapping,
    default_question_assessment_schema,
    default_spiral_reinforcement,
    nextgen_module_doc_template,
    validate_nextgen_lesson,
    validate_nextgen_module,
)


ALLOWLIST = ["pressure_area_confusion", "pressure_force_confusion"]


def _mcq(qid: str, prompt: str, skill_tag: str) -> dict:
    return {
        "id": qid,
        "question_id": qid,
        "type": "mcq",
        "prompt": prompt,
        "choices": ["A", "B", "C", "D"],
        "answer_index": 0,
        "hint": "Use the pressure story.",
        "feedback": ["Use the pressure story."] * 4,
        "misconception_tags": ["pressure_area_confusion"],
        "skill_tags": [skill_tag],
        "assessment_schema": default_question_assessment_schema("mcq", "diagnostic"),
    }


def _short(qid: str, prompt: str, skill_tag: str, phase_key: str = "diagnostic") -> dict:
    return {
        "id": qid,
        "question_id": qid,
        "type": "short",
        "prompt": prompt,
        "accepted_answers": ["because the same force can be spread over different areas"],
        "acceptance_rules": {
            "phrase_groups": [
                ["same force", "same push"],
                ["different areas", "different contact areas", "different footprints"],
            ]
        },
        "hint": "Use force-and-area language.",
        "feedback": ["Use force-and-area language."],
        "misconception_tags": ["pressure_force_confusion"],
        "skill_tags": [skill_tag],
        "assessment_schema": default_question_assessment_schema("short", phase_key),
    }


def _valid_v3_lesson() -> dict:
    return {
        "id": "M5_L1",
        "lesson_id": "M5_L1",
        "module_id": "M5",
        "title": "Pressure patterns",
        "sequence": 1,
        "phases": {
            "diagnostic": {
                "items": [
                    _mcq("M5L1_D1", "Which change lowers pressure most directly?", "area_compare"),
                    _mcq("M5L1_D2", "Which statement keeps force separate from pressure?", "force_pressure_distinction"),
                    _short("M5L1_D3", "Why can the same force create a different pressure?", "concept_explanation"),
                ]
            },
            "analogical_grounding": {
                "analogy_text": "Patch sensors compare how much push reaches each equal patch.",
                "commitment_prompt": "What changes when the same push is crowded onto fewer patches?",
                "micro_prompts": [
                    {"prompt": "Describe the patch load.", "hint": "Keep push and patch count separate."},
                    {"prompt": "Predict the overloaded patch.", "hint": "Smaller spread means greater patch load."},
                ],
            },
            "simulation_inquiry": {
                "lab_id": "m5_pressure_lab",
                "inquiry_prompts": [
                    {"prompt": "Hold force fixed and change area.", "hint": "Watch patch load."},
                    {"prompt": "Hold area fixed and change force.", "hint": "Compare the new reading."},
                ],
            },
            "concept_reconstruction": {
                "prompts": [
                    "Explain pressure in words before using symbols.",
                    "Explain why spread changes the pressure story.",
                ],
                "capsules": [
                    {
                        "prompt": "Check the central idea.",
                        "checks": [
                            {
                                **_mcq("M5L1_C1", "Which statement keeps the ratio idea visible?", "ratio_reasoning"),
                                "assessment_schema": default_question_assessment_schema("mcq", "concept_reconstruction"),
                            },
                            _short("M5L1_C2", "Why does a wider footprint help?", "safety_reasoning", "concept_reconstruction"),
                        ],
                    }
                ],
            },
            "transfer": {
                "items": [
                    {
                        **_mcq("M5L1_T1", "Which redesign keeps the floor safe?", "design_reasoning"),
                        "assessment_schema": default_question_assessment_schema("mcq", "transfer"),
                    },
                    {
                        **_mcq("M5L1_T2", "What must stay fixed if the limit is fixed?", "limit_reasoning"),
                        "assessment_schema": default_question_assessment_schema("mcq", "transfer"),
                    },
                    _short("M5L1_T3", "Why must area rise with force when the limit stays fixed?", "proportional_reasoning", "transfer"),
                ]
            },
        },
        "authoring_contract": {
            "concept_targets": [
                "Distinguish force from pressure",
                "Use pressure as a ratio story before calculating",
            ],
            "core_concepts": [
                "Pressure depends on both force and area.",
                "The same force can create different pressures if the area changes.",
                "Pressure compares push with spread, not push alone.",
                "A safe pressure limit can be used to design backward to a required area.",
            ],
            "technical_words": [
                {
                    "term": "Pressure",
                    "meaning": "Force per unit area.",
                    "why_it_matters": "It keeps force and pressure separate.",
                }
            ],
            "prerequisite_lessons": [],
            "misconception_focus": ["pressure_area_confusion", "pressure_force_confusion"],
            "formulas": [
                {
                    "equation": "P = F/A",
                    "meaning": "Pressure is force divided by area.",
                    "units": ["Pa", "N/m^2"],
                    "conditions": "Use this when a total force is shared over a contact area.",
                }
            ],
            "representations": [
                {"kind": "words", "purpose": "State the patch-load idea in plain language."},
                {"kind": "formula", "purpose": "Compress the ratio into symbols once the story is clear."},
                {"kind": "diagram", "purpose": "Show equal patches sharing the push."},
            ],
            "analogy_map": {
                "comparison": "Patch sensors make pressure a push-per-patch story.",
                "mapping": ["Total push -> force", "Patch spread -> area"],
                "limit": "The model organizes the story but formal units still matter.",
                "prediction_prompt": "Predict what changes when the same push is spread wider.",
            },
            "worked_examples": [
                {
                    "prompt": "A 600 N push acts on 0.30 m^2. Find the pressure.",
                    "steps": ["Use P = F/A.", "Substitute 600/0.30.", "State the answer in pascals."],
                    "final_answer": "2000 Pa",
                    "answer_reason": "Dividing the total force by the contact area gives 2000 pascals.",
                    "why_it_matters": "The ratio story matches the formal equation.",
                },
                {
                    "prompt": "Why can two shoes with the same force give different pressures?",
                    "steps": ["Keep the force fixed.", "Compare the contact areas.", "Link wider area to lower pressure."],
                    "final_answer": "The wider shoe gives lower pressure.",
                    "answer_reason": "The same force spread over a larger area lowers the force per unit area.",
                    "why_it_matters": "This keeps force and pressure distinct.",
                },
            ],
            "visual_assets": [{"asset_id": "m5-l1-patch", "purpose": "Compare equal-patch load.", "caption": "Same push, different spread."}],
            "simulation_contract": {
                "asset_id": "m5_l1_patch_lab",
                "concept": "pressure_solids",
                "baseline_case": "Start with one push on a medium area.",
                "focus_prompt": "How does the patch reading change when the spread changes?",
                "controls": [
                    {"variable": "force", "label": "Push", "why_it_matters": "Total push is one side of the ratio."},
                    {"variable": "area", "label": "Footprint area", "why_it_matters": "Spread is the other side of the ratio."},
                ],
                "readouts": [
                    {"label": "Patch load", "meaning": "Shows the pressure value."},
                    {"label": "Safe margin", "meaning": "Shows how far the design is from the limit."},
                ],
                "comparison_tasks": [
                    "Hold force fixed and halve the area.",
                    "Hold area fixed and double the force.",
                ],
                "watch_for": "Students must keep total push separate from patch load.",
                "takeaway": "Pressure is push per patch, not push alone.",
            },
            "reflection_prompts": ["Explain why a pressure limit is a ratio condition."],
            "mastery_skills": [
                "Distinguish force from pressure",
                "Use P = F/A",
                "Explain area effects in words",
                "Design backward from a safe limit",
                "Compare two pressure situations",
            ],
            "assessment_alignment": default_assessment_alignment(),
            "competency_mapping": default_competency_mapping(),
            "spiral_reinforcement": default_spiral_reinforcement(),
            "variation_plan": {
                "diagnostic": "Rotate the opening check across force-only and area-only misconception cases.",
                "concept_gate": "Retry using a different representation before repeating a stem.",
                "mastery": "Prefer unseen contexts and variable changes before repeating any prior stem.",
            },
            "assessment_bank_targets": {
                "diagnostic_pool_min": 3,
                "concept_gate_pool_min": 2,
                "mastery_pool_min": 3,
                "fresh_attempt_policy": "Prefer unseen lesson-owned questions before repeating a stem.",
            },
            "scaffold_support": {
                "core_idea": "Pressure is push per patch.",
                "reasoning": "Name the total push and spread before using the ratio.",
                "check_for_understanding": "What happens if the same push is spread wider?",
                "common_trap": "Do not confuse total force with pressure.",
                "analogy_bridge": {
                    "body": "Equal sensor patches reveal how crowded the push is.",
                    "check_for_understanding": "What does one patch reading stand for?",
                },
                "extra_sections": [{"heading": "Pressure units", "body": "Pressure is measured in pascals."}],
            },
            "visual_clarity_checks": [
                "The patch labels are fully visible on desktop.",
                "The key equation is fully visible on mobile.",
                "The main readout is not overlapped by arrows or shapes.",
            ],
            "release_checks": [
                "The ratio story is taught before mastery.",
                "The formula is paired with meaning and units.",
                "A non-text representation supports the lesson.",
                "The visual stays readable on desktop and mobile.",
            ],
        },
    }


class LessonAuthoringContractTests(unittest.TestCase):
    def test_module_doc_template_defaults_to_v3(self) -> None:
        module_doc = nextgen_module_doc_template("M5", "Pressure", "Pressure module", ALLOWLIST)
        self.assertEqual(module_doc["authoring_standard"], AUTHORING_STANDARD_V3)

    def test_v3_conceptual_short_answers_require_phrase_groups(self) -> None:
        lesson = _valid_v3_lesson()
        lesson["phases"]["transfer"]["items"][2].pop("acceptance_rules", None)

        errors = validate_nextgen_lesson(lesson, ALLOWLIST, AUTHORING_STANDARD_V3)

        self.assertTrue(any("conceptual short answers need acceptance_rules.phrase_groups" in error for error in errors))

    def test_v3_module_validation_accepts_richer_contract(self) -> None:
        lesson = _valid_v3_lesson()
        module_doc = {
            "id": "M5",
            "module_id": "M5",
            "title": "Pressure",
            "description": "Pressure in solids, liquids, and air.",
            "mastery_outcomes": ["Use pressure in solids.", "Use liquid pressure.", "Use atmospheric pressure.", "Explain pressure conceptually."],
            "misconception_tag_allowlist": ALLOWLIST,
            "content_version": "20260321_m5_contract_ready",
            "authoring_standard": AUTHORING_STANDARD_V3,
        }

        module_lessons = [deepcopy(lesson) for _ in range(6)]
        for index, entry in enumerate(module_lessons, start=1):
            entry["id"] = f"M5_L{index}"
            entry["lesson_id"] = f"M5_L{index}"
            entry["title"] = f"Lesson {index}"
            entry["sequence"] = index
        sim_labs = [{"lab_id": f"m5_l{index}_lab"} for index in range(1, 7)]

        validate_nextgen_module(module_doc, module_lessons, sim_labs, ALLOWLIST)

    def test_technical_words_require_term_and_meaning_when_present(self) -> None:
        lesson = _valid_v3_lesson()
        lesson["authoring_contract"]["technical_words"] = [{"term": "Pressure"}]

        errors = validate_nextgen_lesson(lesson, ALLOWLIST, AUTHORING_STANDARD_V3)

        self.assertTrue(any("technical_words[1] needs a meaning" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
