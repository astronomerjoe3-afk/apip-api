# Lesson Authoring Spec v2

Use this spec for every new next-generation module from this point forward.

## Non-negotiables

- Teach every relationship before mastery tests it.
- Pair every formula with meaning, units, and conditions.
- Include at least one non-text representation in every lesson.
- Vary fresh attempts by context, numbers, or representation.
- Keep mastery distinct from diagnostics.
- Use analogies with mapping and limitation, not slogan-only wording.
- Give every simulation a real variable change, comparison task, and takeaway.
- Release nothing that still depends on generic fallback teaching.
- Put scaffold-teaching copy in the authored contract so the web runner does not need lesson-code rescue text.
- Give conceptual short answers authored acceptance rules when equivalent phrasings should score.
- Make worked examples state both the final answer and why that answer follows.

## Required Lesson Package

Every lesson must ship with:

- identity: id, lesson_id, module_id, sequence, title, updated_utc
- phases: diagnostic, analogical_grounding, simulation_inquiry, concept_reconstruction, transfer
- authoring_contract: concept_targets, prerequisite_lessons, misconception_focus, formulas, representations, analogy_map, worked_examples, visual_assets, simulation_contract, reflection_prompts, mastery_skills, variation_plan, scaffold_support, release_checks
- short questions may also include acceptance_rules.phrase_groups when literal accepted answers are not enough

## Minimum Content Standard

- diagnostic: at least 3 misconception-targeted items
- analogy: text, commitment prompt, and at least 2 micro-prompts
- simulation: lab id, baseline case, and at least 2 inquiry prompts
- reconstruction: at least 2 explanation prompts and one capsule check set
- transfer: at least 3 items in a new context or representation
- worked examples: at least 2, including one contrast or non-example
- worked examples: include prompt, explicit reasoning steps, final answer, answer_reason, and why_it_matters
- mastery skills: at least 5 distinct skills so the bank stays broad under adaptation
- visuals: at least 1 core visual that states the key relationship clearly
- scaffold support: authored core idea, reasoning path, check-for-understanding, common trap, analogy bridge, and any pre-simulation extra sections

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
