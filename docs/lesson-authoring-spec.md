# Lesson Authoring Spec v1

Use this spec for every next-generation module from F4 onward.

## Non-negotiables

- Teach every relationship before mastery tests it.
- Pair every formula with meaning, units, and conditions.
- Include at least one non-text representation in every lesson.
- Vary fresh attempts by context, numbers, or representation.
- Keep mastery distinct from diagnostics.
- Use analogies with mapping and limitation, not slogan-only wording.
- Give every simulation a real variable change, comparison task, and takeaway.
- Release nothing that still depends on generic fallback teaching.

## Required Lesson Package

Every lesson must ship with:

- identity: id, lesson_id, module_id, sequence, title, updated_utc
- phases: diagnostic, analogical_grounding, simulation_inquiry, concept_reconstruction, transfer
- authoring_contract: concept_targets, prerequisite_lessons, misconception_focus, formulas, representations, analogy_map, worked_examples, visual_assets, simulation_contract, reflection_prompts, mastery_skills, variation_plan, release_checks

## Minimum Content Standard

- diagnostic: at least 3 misconception-targeted items
- analogy: text, commitment prompt, and at least 2 micro-prompts
- simulation: lab id, baseline case, and at least 2 inquiry prompts
- reconstruction: at least 2 explanation prompts and one capsule check set
- transfer: at least 3 items in a new context or representation
- worked examples: at least 2, including one contrast or non-example
- mastery skills: at least 5 distinct skills so the bank stays broad under adaptation
- visuals: at least 1 core visual that states the key relationship clearly

## Module Standard

Every F4+ module must include:

- content_version
- authoring_standard
- misconception allowlist
- mastery outcomes
- one simulation or lab config per lesson
- at least 6 lessons with a coherent progression from prerequisite ideas to deeper synthesis

## Implementation

Author against these helpers first:

- scripts/lesson_authoring_contract.py
- scripts/nextgen_module_scaffold.py
