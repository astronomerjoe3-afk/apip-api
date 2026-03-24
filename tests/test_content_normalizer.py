from __future__ import annotations

import unittest

from app.services.content_normalizer import to_student_lesson_view


class ContentNormalizerTests(unittest.TestCase):
    def test_student_view_keeps_authored_contract_subset_and_short_answer_rules(self) -> None:
        lesson = {
            "id": "M3_L1",
            "lesson_id": "M3_L1",
            "module_id": "M3",
            "title": "Work Done and Energy Transfer",
            "sequence": 1,
            "phases": {
                "analogical_grounding": {
                    "analogy_text": "Energy Ledger",
                    "micro_prompts": [{"prompt": "Prompt", "hint": "Hint"}],
                },
                "simulation_inquiry": {
                    "lab_id": "m3_work_transfer_lab",
                    "inquiry_prompts": [{"prompt": "Compare", "hint": "Watch the transfer"}],
                },
                "concept_reconstruction": {
                    "prompts": ["Explain the idea."],
                    "capsules": [
                        {
                            "prompt": "Capsule",
                            "checks": [
                                {
                                    "id": "M3L1_C1",
                                    "type": "short",
                                    "prompt": "Why is no work done on the wall?",
                                    "accepted_answers": ["because it does not move"],
                                    "acceptance_rules": {
                                        "phrase_groups": [
                                            ["no displacement", "does not move"],
                                            ["force", "push"],
                                        ]
                                    },
                                    "skill_tags": ["work_story", "concept_explanation"],
                                    "hint": "Work needs force and displacement together.",
                                    "feedback": ["Work needs force and displacement together."],
                                }
                            ],
                        }
                    ],
                },
                "diagnostic": {"items": []},
                "transfer": {"items": []},
            },
            "authoring_contract": {
                "core_concepts": [
                    "Work depends on force and displacement together.",
                    "No displacement in the force direction means no work in the simple model.",
                    "The same work can be described as an energy transfer.",
                    "Choose the equation that matches the story before calculating.",
                ],
                "technical_words": [
                    {
                        "term": "Work done",
                        "meaning": "Energy transferred when a force acts through a distance.",
                        "why_it_matters": "It links force stories to energy transfer.",
                    }
                ],
                "worked_examples": [
                    {
                        "prompt": "A 4 N force moves a box 5 m. Find the work done.",
                        "steps": ["Use W = Fd.", "Multiply 4 by 5."],
                        "final_answer": "20 J",
                        "answer_reason": "Force and displacement act together, so W = 4 x 5 = 20 J.",
                        "why_it_matters": "This anchors work to transferred energy.",
                    }
                ],
                "visual_assets": [{"asset_id": "m3-l1-work", "purpose": "Show transfer", "caption": "Work transfers energy."}],
                "animation_assets": [{"asset_id": "m3-l1-work-anim"}],
                "simulation_contract": {"baseline_case": "Start with a moving crate."},
                "assessment_bank_targets": {"mastery_pool_min": 5},
                "scaffold_support": {
                    "core_idea": "Work needs force and displacement together.",
                    "reasoning": "Check the story before multiplying.",
                    "check_for_understanding": "What if the wall does not move?",
                    "common_trap": "Force alone is not enough.",
                    "analogy_bridge": {
                        "body": "Tokens appear only when motion happens.",
                        "check_for_understanding": "When does the ledger change?",
                    },
                },
                "visual_clarity_checks": [
                    "The force arrow label is fully visible.",
                    "The equation callout is visible on mobile.",
                    "The readout text does not overlap the diagram.",
                ],
            },
        }

        payload = to_student_lesson_view(lesson)

        capsule_check = payload["phases"]["concept_reconstruction"]["capsules"][0]["checks"][0]
        self.assertEqual(
            capsule_check["acceptance_rules"]["phrase_groups"],
            [["no displacement", "does not move"], ["force", "push"]],
        )
        self.assertEqual(capsule_check["skill_tags"], ["work_story", "concept_explanation"])

        self.assertEqual(
            payload["authoring_contract"]["scaffold_support"]["core_idea"],
            "Work needs force and displacement together.",
        )
        self.assertEqual(
            payload["authoring_contract"]["core_concepts"][0],
            "Work depends on force and displacement together.",
        )
        self.assertEqual(
            payload["authoring_contract"]["technical_words"][0]["term"],
            "Work done",
        )
        self.assertEqual(
            payload["authoring_contract"]["technical_words"][0]["source"],
            "authored",
        )
        self.assertEqual(
            payload["authoring_contract"]["worked_examples"][0]["answer_reason"],
            "Force and displacement act together, so W = 4 x 5 = 20 J.",
        )
        self.assertEqual(
            payload["authoring_contract"]["visual_clarity_checks"][1],
            "The equation callout is visible on mobile.",
        )
        self.assertEqual(
            payload["authoring_contract"]["assessment_alignment"]["exam_board"],
            "Cambridge IGCSE",
        )
        self.assertEqual(
            payload["authoring_contract"]["competency_mapping"]["metrics"][0]["key"],
            "igcse_readiness_score",
        )
        self.assertEqual(
            payload["authoring_contract"]["spiral_reinforcement"]["lesson_stage_focus"][0]["stage"],
            "quantitative",
        )

    def test_student_view_adds_curriculum_defaults_for_older_lessons(self) -> None:
        lesson = {
            "id": "M10_L3",
            "lesson_id": "M10_L3",
            "module_id": "M10",
            "title": "Voltage around a loop",
            "sequence": 3,
            "phases": {
                "analogical_grounding": {},
                "simulation_inquiry": {},
                "concept_reconstruction": {"capsules": []},
                "diagnostic": {"items": []},
                "transfer": {"items": []},
            },
            "authoring_contract": {},
        }

        payload = to_student_lesson_view(lesson)
        contract = payload["authoring_contract"]

        self.assertEqual(contract["assessment_alignment"]["exam_board"], "Cambridge IGCSE")
        self.assertEqual(
            [paper["paper_id"] for paper in contract["assessment_alignment"]["paper_structure"]],
            ["paper_1", "paper_2", "paper_4", "paper_5", "paper_6"],
        )
        self.assertEqual(
            [metric["key"] for metric in contract["competency_mapping"]["metrics"]],
            [
                "igcse_readiness_score",
                "topic_mastery_index",
                "practical_competency_rating",
                "exam_simulation_performance",
            ],
        )
        self.assertEqual(
            contract["spiral_reinforcement"]["lesson_stage_focus"][0]["stage"],
            "quantitative",
        )
        self.assertEqual(
            contract["spiral_reinforcement"]["lesson_stage_focus"][0]["level"],
            "level_2",
        )
        self.assertGreaterEqual(len(contract["technical_words"]), 4)
        self.assertEqual(contract["technical_words"][0]["term"], "Charge")
        self.assertEqual(
            contract["technical_words"][1]["term"],
            "Current",
        )
        self.assertTrue(all(entry["source"] == "generated" for entry in contract["technical_words"]))

    def test_student_view_adds_technical_words_for_advanced_module_aliases(self) -> None:
        lesson = {
            "id": "MA5_L1",
            "lesson_id": "MA5_L1",
            "module_id": "MA5",
            "title": "Modern physics launch",
            "sequence": 1,
            "phases": {
                "analogical_grounding": {},
                "simulation_inquiry": {},
                "concept_reconstruction": {"capsules": []},
                "diagnostic": {"items": []},
                "transfer": {"items": []},
            },
            "authoring_contract": {},
        }

        payload = to_student_lesson_view(lesson)
        technical_words = payload["authoring_contract"]["technical_words"]
        terms = [entry["term"] for entry in technical_words]

        self.assertGreaterEqual(len(technical_words), 4)
        self.assertEqual(
            terms[:4],
            [
                "Photoelectric effect",
                "Photon",
                "Wave-particle duality",
                "Time dilation",
            ],
        )
        self.assertTrue(all(entry["source"] == "generated" for entry in technical_words))

    def test_student_view_expands_short_answer_acceptance_margin_to_ten_to_fourteen_versions(self) -> None:
        lesson = {
            "id": "M14_L2",
            "lesson_id": "M14_L2",
            "module_id": "M14",
            "title": "Choose the Star Path",
            "sequence": 2,
            "phases": {
                "analogical_grounding": {},
                "simulation_inquiry": {},
                "concept_reconstruction": {
                    "capsules": [
                        {
                            "prompt": "Capsule",
                            "checks": [
                                {
                                    "id": "M14L2_C8",
                                    "type": "short",
                                    "prompt": "Why does the same beginning not guarantee the same ending?",
                                    "accepted_answers": [
                                        "Because stars can begin similarly but diverge later if their masses are different."
                                    ],
                                    "acceptance_rules": {
                                        "phrase_groups": [
                                            ["mass", "different mass"],
                                            ["different", "branch"],
                                            ["ending", "remnant"],
                                        ]
                                    },
                                    "skill_tags": ["mass_life_path"],
                                    "hint": "Keep shared start and different ending together.",
                                    "feedback": ["Keep shared start and different ending together."],
                                }
                            ],
                        }
                    ]
                },
                "diagnostic": {"items": []},
                "transfer": {"items": []},
            },
            "authoring_contract": {},
        }

        payload = to_student_lesson_view(lesson)
        accepted = payload["phases"]["concept_reconstruction"]["capsules"][0]["checks"][0]["accepted_answers"]

        self.assertGreaterEqual(len(accepted), 10)
        self.assertLessEqual(len(accepted), 15)
        self.assertIn("mass matters", [answer.lower() for answer in accepted])


if __name__ == "__main__":
    unittest.main()
