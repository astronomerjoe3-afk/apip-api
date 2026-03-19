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
            payload["authoring_contract"]["worked_examples"][0]["answer_reason"],
            "Force and displacement act together, so W = 4 x 5 = 20 J.",
        )


if __name__ == "__main__":
    unittest.main()
