from __future__ import annotations

import unittest

from scripts.lesson_authoring_contract import AUTHORING_STANDARD_V3
from scripts.nextgen_module_builder import _question, build_nextgen_module_bundle


ALLOWLIST = ["test_tag_a", "test_tag_b"]
RELEASE_CHECKS = [
    "Every mastery-tested relationship is explicitly taught before mastery.",
    "Every formula is shown with meaning, units, and conditions.",
    "At least one non-text representation is used and checked.",
    "Visuals are readable on desktop and mobile.",
]


def _mcq_spec(qid: str, prompt: str, skill_tag: str) -> dict:
    return {
        "id": qid,
        "kind": "mcq",
        "prompt": prompt,
        "choices": ["A", "B", "C", "D"],
        "answer_index": 1,
        "hint": "Use the taught comparison.",
        "misconception_tags": ["test_tag_a"],
        "skill_tags": [skill_tag],
    }


def _short_spec(qid: str, prompt: str, skill_tag: str) -> dict:
    return {
        "id": qid,
        "kind": "short",
        "prompt": prompt,
        "accepted_answers": ["because the relationship must be explained in words"],
        "acceptance_rules": {
            "phrase_groups": [
                ["relationship", "link", "connection"],
                ["in words", "verbally", "in explanation form"],
            ]
        },
        "hint": "Explain the relationship in a sentence.",
        "misconception_tags": ["test_tag_b"],
        "skill_tags": [skill_tag],
    }


def _lesson_spec(index: int) -> dict:
    lesson_id = f"TST_L{index}"
    return {
        "id": lesson_id,
        "title": f"Test Lesson {index}",
        "sim": {
            "lab_id": f"tst_l{index}_lab",
            "title": f"Test Lab {index}",
            "description": "A small lab used to validate authored contract defaults.",
            "instructions": ["Run the baseline case.", "Change one control at a time."],
            "outcomes": ["Students compare the readout changes."],
            "fields": ["input_value", "output_value"],
            "depth": "A compact validation lab.",
        },
        "diagnostic": [
            _mcq_spec(f"{lesson_id}_D1", "Which opening idea is correct?", "diagnostic_compare"),
            _mcq_spec(f"{lesson_id}_D2", "Which misconception is being corrected?", "diagnostic_misconception"),
            _short_spec(f"{lesson_id}_D3", "Why is the opening idea framed this way?", "diagnostic_explanation"),
        ],
        "analogy_text": "A simple analogy keeps the concept coherent before formal terminology appears.",
        "commitment_prompt": "What do you predict will stay the same when the representation changes?",
        "micro_prompts": [
            {"prompt": "Describe the analogy in plain words.", "hint": "Keep the key comparison visible."},
            {"prompt": "State one limit of the analogy.", "hint": "Name what the analogy cannot do exactly."},
        ],
        "inquiry": [
            {"prompt": "Run the baseline case.", "hint": "Record the first readout."},
            {"prompt": "Change one control.", "hint": "Look for the changed output."},
        ],
        "recon_prompts": [
            "State the concept in words before symbol use.",
            "Connect the idea to the formal rule.",
        ],
        "capsule_prompt": "Check the taught idea in a quick new representation.",
        "capsule_checks": [
            _mcq_spec(f"{lesson_id}_C1", "Which statement keeps the concept intact?", "concept_compare"),
            _short_spec(f"{lesson_id}_C2", "Why does the concept still hold in this representation?", "concept_explanation"),
        ],
        "transfer": [
            _mcq_spec(f"{lesson_id}_T1", "Which calculation setup is valid?", "transfer_setup"),
            _mcq_spec(f"{lesson_id}_T2", "Which result interpretation is justified?", "transfer_interpret"),
            _short_spec(f"{lesson_id}_T3", "Explain how the relationship transfers to the new case.", "transfer_explanation"),
        ],
        "contract": {
            "concept_targets": [
                "Teach the governing relationship conceptually.",
                "Use the relationship in a structured problem.",
            ],
            "core_concepts": [
                "The lesson introduces the relationship in words.",
                "The lesson returns to the relationship in symbols.",
                "The same idea survives a changed representation.",
                "Students should explain the relationship before calculating.",
            ],
            "prerequisite_lessons": [],
            "misconception_focus": ["test_tag_a", "test_tag_b"],
            "formulas": [
                {
                    "equation": "x = y/z",
                    "meaning": "A placeholder ratio keeps the template valid.",
                    "units": ["arb. unit"],
                    "conditions": "Use only in this contract test fixture.",
                }
            ],
            "representations": [
                {"kind": "words", "purpose": "State the relationship in plain language."},
                {"kind": "formula", "purpose": "State the relationship symbolically."},
                {"kind": "diagram", "purpose": "Show a visual form of the same idea."},
            ],
            "analogy_map": {
                "comparison": "The analogy ties the new rule to a familiar structure.",
                "mapping": ["Analogy feature -> formal quantity", "Analogy action -> formal change"],
                "limit": "The analogy is a bridge, not the full formal model.",
                "prediction_prompt": "Predict what happens when one quantity changes.",
            },
            "worked_examples": [
                {
                    "prompt": "Use the taught relationship once.",
                    "steps": ["Identify the quantities.", "Apply the relationship.", "State the result."],
                    "final_answer": "A valid example answer.",
                    "answer_reason": "The worked example mirrors the taught relationship.",
                    "why_it_matters": "It shows how the concept becomes a calculation.",
                },
                {
                    "prompt": "Explain the same relationship in words.",
                    "steps": ["Name the comparison.", "State the link.", "Finish with the conclusion."],
                    "final_answer": "A valid conceptual answer.",
                    "answer_reason": "The reasoning matches the taught concept.",
                    "why_it_matters": "It keeps the lesson from becoming formula-only.",
                },
            ],
            "visual_assets": [
                {"asset_id": f"{lesson_id.lower()}-visual.svg", "purpose": "Support the taught comparison.", "caption": "A clean diagram for the lesson."}
            ],
            "simulation_contract": {
                "asset_id": f"{lesson_id.lower()}-lab",
                "concept": "contract_test_concept",
                "baseline_case": "Start from the simplest case.",
                "focus_prompt": "Which variable change matters most?",
                "controls": [
                    {"variable": "input_value", "label": "Input", "why_it_matters": "It lets the concept vary."},
                    {"variable": "comparison_case", "label": "Comparison", "why_it_matters": "It provides contrast."},
                ],
                "readouts": [
                    {"label": "Output", "meaning": "Shows the resulting change."},
                    {"label": "Comparison note", "meaning": "Explains the new case."},
                ],
                "comparison_tasks": [
                    "Compare the baseline and changed case.",
                    "Explain which variable mattered most.",
                ],
                "watch_for": "Students should connect the readout to the taught relationship.",
                "takeaway": "The relationship survives a fresh representation.",
            },
            "reflection_prompts": ["Explain what stays constant across the lesson representations."],
            "mastery_skills": [
                "State the concept in words",
                "Use the formal relationship",
                "Interpret a structured result",
                "Transfer the idea to a new case",
                "Explain the reasoning behind the result",
            ],
            "variation_plan": {
                "diagnostic": "Rotate the opening prompt across contexts and representations.",
                "concept_gate": "Use a fresh representation before repeating a stem.",
                "mastery": "Prefer unseen question contexts before repeating any old stem.",
            },
            "assessment_bank_targets": {
                "diagnostic_pool_min": 3,
                "concept_gate_pool_min": 2,
                "mastery_pool_min": 3,
                "fresh_attempt_policy": "Prefer unseen authored questions before repeating a stem.",
            },
            "scaffold_support": {
                "core_idea": "A single relationship sits underneath the lesson.",
                "reasoning": "State the idea in words before calculation.",
                "check_for_understanding": "What stays the same when the representation changes?",
                "common_trap": "Do not jump to calculation before naming the relationship.",
                "analogy_bridge": {
                    "body": "The analogy helps students keep the relationship coherent.",
                    "check_for_understanding": "Which part of the analogy maps to the formal quantity?",
                },
                "extra_sections": [],
            },
            "visual_clarity_checks": [
                "No label is clipped on desktop.",
                "No label is clipped on mobile.",
                "The main relationship is readable without overlap.",
            ],
        },
    }


class AssessmentSchemaContractTests(unittest.TestCase):
    def test_question_builder_adds_default_assessment_schema(self) -> None:
        diagnostic = _question(_mcq_spec("Q1", "Which idea is correct?", "diagnostic_compare"), ALLOWLIST, "diagnostic")
        transfer = _question(_short_spec("Q2", "Explain the transferred relationship.", "transfer_explanation"), ALLOWLIST, "transfer")

        self.assertEqual(
            diagnostic["assessment_schema"],
            {
                "exam_paper": "paper_1",
                "exam_style": "multiple_choice",
                "spiral_level": "level_1",
                "spiral_stage": "intuitive",
                "competency_tags": ["igcse_readiness_score", "topic_mastery_index"],
            },
        )
        self.assertEqual(transfer["assessment_schema"]["exam_paper"], "paper_2")
        self.assertEqual(transfer["assessment_schema"]["exam_style"], "structured")
        self.assertEqual(transfer["assessment_schema"]["spiral_level"], "level_2")
        self.assertEqual(transfer["assessment_schema"]["spiral_stage"], "quantitative")
        self.assertEqual(
            transfer["assessment_schema"]["competency_tags"],
            ["topic_mastery_index", "exam_simulation_performance"],
        )

    def test_builder_injects_contract_defaults_for_v3_lessons(self) -> None:
        module_spec = {
            "module_description": "A compact contract test module.",
            "mastery_outcomes": [
                "Explain the concept in words.",
                "Use the concept quantitatively.",
                "Interpret the result in a fresh case.",
                "Connect conceptual and quantitative views.",
            ],
            "lessons": [_lesson_spec(index) for index in range(1, 7)],
        }

        _, lessons, _ = build_nextgen_module_bundle(
            module_id="TST",
            module_title="Contract Test Module",
            module_spec=module_spec,
            allowlist=ALLOWLIST,
            content_version="20260322_assessment_schema_contract",
            release_checks=RELEASE_CHECKS,
            sequence=99,
            level="Core",
            estimated_minutes=45,
            authoring_standard=AUTHORING_STANDARD_V3,
        )

        lesson = lessons[0][1]
        contract = lesson["authoring_contract"]

        self.assertEqual(contract["assessment_alignment"]["exam_board"], "Cambridge IGCSE")
        self.assertEqual(
            [item["paper_id"] for item in contract["assessment_alignment"]["paper_structure"]],
            ["paper_1", "paper_2", "paper_4", "paper_5", "paper_6"],
        )
        self.assertEqual(
            contract["assessment_alignment"]["auto_generation_outputs"],
            ["timed_mock_exams", "topic_level_past_paper_simulations", "weakness_heatmaps"],
        )
        self.assertEqual(
            [item["key"] for item in contract["competency_mapping"]["metrics"]],
            [
                "igcse_readiness_score",
                "topic_mastery_index",
                "practical_competency_rating",
                "exam_simulation_performance",
            ],
        )
        self.assertEqual(
            [(item["level"], item["stage"]) for item in contract["spiral_reinforcement"]["stages"]],
            [
                ("level_1", "intuitive"),
                ("level_2", "quantitative"),
                ("level_3", "analytical_derivation"),
            ],
        )

        diagnostic_item = lesson["phases"]["diagnostic"]["items"][0]
        concept_item = lesson["phases"]["concept_reconstruction"]["capsules"][0]["checks"][0]
        transfer_item = lesson["phases"]["transfer"]["items"][-1]

        self.assertEqual(diagnostic_item["assessment_schema"]["exam_style"], "multiple_choice")
        self.assertEqual(diagnostic_item["assessment_schema"]["spiral_stage"], "intuitive")
        self.assertEqual(concept_item["assessment_schema"]["exam_paper"], "paper_1")
        self.assertEqual(transfer_item["assessment_schema"]["exam_paper"], "paper_2")
        self.assertEqual(transfer_item["assessment_schema"]["spiral_level"], "level_2")


if __name__ == "__main__":
    unittest.main()
