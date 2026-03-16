# Lesson Assets Pipeline

This pipeline keeps lesson pedagogy and lesson media generation separate.

## Handoff Contract

Codex should emit one lesson spec JSON per lesson with:

- `lesson_id`
- `module_id`
- `title`
- `phases`
- `asset_requests`

The orchestrator compiles those requests into generated files plus a lesson patch:

- `generated_assets`
- `lesson_patch`

`lesson_patch` is the Firestore-ready payload Codex can merge into the canonical lesson document.

## Components

- `app/lesson_pipeline/contracts.py`
  Defines the spec and compiled-manifest dataclasses.
- `app/agents/diagram_agent.py`
  Generates SVG lesson diagrams.
- `app/agents/animation_agent.py`
  Generates HTML concept animations.
- `app/agents/simulation_agent.py`
  Generates browser-native simulation bundles.
- `app/lesson_pipeline/lesson_asset_orchestrator.py`
  Runs the requested agents and assembles the compiled package.
- `scripts/compile_lesson_assets.py`
  CLI entrypoint for compiling a Codex-authored lesson spec.

## Example Flow

1. Codex writes `lesson_specs/F1_L1.json`.
2. Run the compile script.
3. Persist `lesson_patch` into the lesson document.
4. Preserve `generated_assets` as build metadata if desired.

## Compile Command

```powershell
& 'C:\Users\User\AppData\Local\Programs\Python\Python312\python.exe' `
  scripts\compile_lesson_assets.py `
  --spec lesson_specs\F1_L1.json `
  --asset-root lesson_assets `
  --public-base /lesson_assets `
  --out lesson_specs\F1_L1.compiled.json
```

## Frontend Rendering

- Render `phase.assets[]` diagrams with `<img>`.
- Render `phase.assets[]` animations with an `<iframe>` or embedded document frame.
- Render `phase.generated_lab.url` in the simulation phase.
