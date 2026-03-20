# Lesson Authoring Spec v3

Use this spec for every newly generated next-generation module from this point forward.

## Non-negotiables

- Teach every relationship before mastery tests it.
- Keep module introductions concise and curriculum-facing; put the analogy world inside the lesson content, not the module introduction.
- Put general core concepts in authored content; do not freeze one-off worked-example numbers into support bullets.
- Pair every formula with meaning, units, and conditions.
- Include at least one non-text representation in every lesson.
- Give every conceptual short answer authored phrase groups so valid student wording can score.
- Tag every authored assessment item with at least one skill tag so coverage and variation stay explicit.
- Vary fresh attempts by context, numbers, or representation.
- Keep mastery distinct from diagnostics.
- Use analogies with mapping and limitation, not slogan-only wording.
- Give every simulation a real variable change, comparison task, and takeaway.
- Release nothing that still depends on generic fallback teaching.
- Put scaffold-teaching copy in the authored contract so the web runner does not need lesson-code rescue text.
- Make worked examples state both the final answer and why that answer follows.
- Add explicit visual clarity checks so labels, equations, and captions stay readable on desktop and mobile.

## Required Lesson Package

Every lesson must ship with:

- identity: `id`, `lesson_id`, `module_id`, `sequence`, `title`, `updated_utc`
- phases: `diagnostic`, `analogical_grounding`, `simulation_inquiry`, `concept_reconstruction`, `transfer`
- authoring_contract:
  - `concept_targets`
  - `core_concepts`
  - `prerequisite_lessons`
  - `misconception_focus`
  - `formulas`
  - `representations`
  - `analogy_map`
  - `worked_examples`
  - `visual_assets`
  - `simulation_contract`
  - `reflection_prompts`
  - `mastery_skills`
  - `variation_plan`
  - `assessment_bank_targets`
  - `scaffold_support`
  - `visual_clarity_checks`
  - `release_checks`
- short conceptual questions must also include `acceptance_rules.phrase_groups`

## Minimum Content Standard

- diagnostic: at least 3 misconception-targeted items
- analogy: text, commitment prompt, and at least 2 micro-prompts
- simulation: lab id, baseline case, focus prompt, at least 2 controls, at least 2 readouts, and at least 2 inquiry prompts
- reconstruction: at least 2 explanation prompts and one capsule check set
- transfer: at least 3 items in a new context or representation
- worked examples: at least 2, including one contrast or non-example
- worked examples: include prompt, explicit reasoning steps, final answer, `answer_reason`, and `why_it_matters`
- mastery skills: at least 5 distinct skills so the bank stays broad under adaptation
- core concepts: at least 4 general statements, written as principles rather than frozen example arithmetic
- visuals: at least 1 core visual that states the key relationship clearly
- scaffold support: authored core idea, reasoning path, check-for-understanding, common trap, analogy bridge, and any pre-simulation extra sections
- visual clarity checks: at least 3 concrete readability checks

## Question Authoring Standard

- every question must include at least one `misconception_tag`
- every v3 question must include at least one `skill_tag`
- conceptual short answers must include authored phrase groups that capture equivalent correct wording
- numeric short answers may omit phrase groups if exact/numeric matching is enough
- aim for distinct skill coverage across phases:
  - diagnostic: at least 2 distinct skill tags
  - concept gate: at least 2 distinct skill tags
  - mastery: at least 3 distinct skill tags

## Simulation Contract Standard

Every v3 lesson simulation contract should name:

- `asset_id`
- `concept`
- `baseline_case`
- `focus_prompt`
- `controls`:
  - each control needs `variable`, `label`, and `why_it_matters`
- `readouts`:
  - each readout needs `label` and `meaning`
- `comparison_tasks`
- `watch_for`
- `takeaway`

This is the minimum needed to keep future explorers lesson-specific rather than generic fallbacks.

## Assessment Standard

Every v3 lesson must include:

- authored `assessment_bank_targets`
- a `fresh_attempt_policy` that prefers unseen lesson-owned questions
- enough authored items that retries can rotate by context, numbers, or representation
- a balance of conceptual and calculation-style checks where the topic genuinely supports both

## Module Standard

Every F4+ module must include:

- `content_version`
- `authoring_standard`
- misconception allowlist
- mastery outcomes
- one simulation or lab config per lesson
- at least 6 lessons with a coherent progression from prerequisite ideas to deeper synthesis

## Implementation

Author against these helpers first:

- `scripts/lesson_authoring_contract.py`
- `scripts/nextgen_module_scaffold.py`
