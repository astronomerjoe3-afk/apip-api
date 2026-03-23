from app.schemas.student import StudentLessonOut


def test_student_lesson_schema_preserves_authoring_formulas() -> None:
    lesson = StudentLessonOut.model_validate(
        {
            "lesson_id": "M1_L4",
            "title": "Constant acceleration forecast",
            "authoring_contract": {
                "formulas": [
                    {
                        "equation": "v = u + at",
                        "meaning": "Final velocity after constant acceleration.",
                        "units": ["m s^-1"],
                        "conditions": "Use only when acceleration is constant.",
                    }
                ]
            },
        }
    )

    assert lesson.authoring_contract.formulas == [
        {
            "equation": "v = u + at",
            "meaning": "Final velocity after constant acceleration.",
            "units": ["m s^-1"],
            "conditions": "Use only when acceleration is constant.",
        }
    ]
