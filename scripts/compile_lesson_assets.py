from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.lesson_pipeline.contracts import LessonSpec
from app.lesson_pipeline.lesson_asset_orchestrator import compile_lesson_assets


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compile lesson media assets from a Codex-authored lesson spec."
    )
    parser.add_argument("--spec", required=True, help="Path to a lesson spec JSON file.")
    parser.add_argument(
        "--asset-root",
        required=True,
        help="Root directory where generated lesson assets should be written.",
    )
    parser.add_argument(
        "--public-base",
        default="/lesson_assets",
        help="Public URL base that maps to the asset root.",
    )
    parser.add_argument(
        "--out",
        default="",
        help="Optional output path for the compiled lesson manifest JSON.",
    )
    args = parser.parse_args()

    spec = LessonSpec.load(args.spec)
    compiled = compile_lesson_assets(
        spec=spec,
        asset_root=args.asset_root,
        public_base=args.public_base,
    )

    output_path = args.out
    if not output_path:
        spec_path = Path(args.spec)
        output_path = str(spec_path.with_name(f"{spec_path.stem}.compiled.json"))

    Path(output_path).write_text(
        json.dumps(compiled.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(
        json.dumps(
            {
                "ok": True,
                "lesson_id": compiled.lesson_id,
                "module_id": compiled.module_id,
                "output_manifest": output_path,
                "diagram_count": len(compiled.generated_assets.get("diagrams") or []),
                "animation_count": len(compiled.generated_assets.get("animations") or []),
                "simulation_generated": bool(compiled.generated_assets.get("simulation")),
            }
        )
    )


if __name__ == "__main__":
    main()
