from __future__ import annotations

try:
    from scripts.revised_phase3_modules_a1_a5 import (
        A2_CONTENT_VERSION,
        A2_LESSONS,
        A2_MODULE_DOC,
        A2_SIM_LABS,
        seed_module_cli,
    )
except ModuleNotFoundError:
    from revised_phase3_modules_a1_a5 import (
        A2_CONTENT_VERSION,
        A2_LESSONS,
        A2_MODULE_DOC,
        A2_SIM_LABS,
        seed_module_cli,
    )


if __name__ == "__main__":
    seed_module_cli("A2")
