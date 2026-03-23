from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List


DIAGRAM_REQUEST_TEMPLATE_CONTRACTS: Dict[str, Dict[str, Any]] = {
    "general_visual": {
        "description": "General educational concept visuals rendered through the image-backed concept-art agent with a deterministic SVG fallback.",
        "concept_aliases": [
            "general_visual",
            "general_visual_concept",
            "illustration",
            "concept_art",
            "power_image",
        ],
        "template_aliases": [
            "general_visual",
        ],
        "meta_contract": {
            "subject": "optional string describing the scene subject",
            "style": "optional style string, defaults to cinematic educational concept art",
            "mood": "optional mood string",
            "composition": "optional composition guidance",
            "palette": "optional palette guidance",
            "avoid_text_in_image": "optional boolean, defaults to true",
            "extra_prompt": "optional extra prompt guidance",
            "model": "optional image model override, defaults to gpt-image-1",
            "quality": "optional quality override",
            "output_format": ["png", "jpeg", "webp"],
            "background": ["auto", "opaque", "transparent"],
        },
    },
    "space_astrophysics_diagram": {
        "description": "Deterministic SVG space and astrophysics diagrams for authored lesson assets.",
        "concept_aliases": [
            "space_astrophysics_diagram",
            "space_diagram",
            "astrophysics_diagram",
            "astronomy_diagram",
        ],
        "template_aliases": [
            "space_astrophysics_diagram",
            "astronomy_diagram",
        ],
        "meta_contract": {
            "diagram_type": [
                "solar_system_overview",
                "lunar_phases",
                "earth_sun_seasons",
                "elliptical_orbit",
                "hr_diagram",
                "stellar_lifecycle",
                "star_vs_planet",
                "galaxy_milky_way",
                "light_year_scale",
                "redshift_expansion",
                "big_bang_timeline",
            ],
            "title": "optional string override",
            "subtitle": "optional string subtitle",
            "show_labels": "optional boolean, defaults to true",
            "note_not_to_scale": "optional boolean, defaults to true",
            "highlighted_body": "optional body label to emphasize in solar-system diagrams",
        },
    },
    "standard_physics_equation": {
        "description": "Deterministic SVG equation cards and equation sheets for reusable physics formula visuals.",
        "concept_aliases": [
            "standard_physics_equation",
            "equation_visual",
            "equation_card",
            "formula_card",
        ],
        "template_aliases": [
            "standard_physics_equation",
        ],
        "meta_contract": {
            "visual_type": ["equation_card", "equation_sheet"],
            "equation_key": [
                "newtons_second_law",
                "ohms_law",
                "wave_speed",
                "density",
                "momentum",
                "kinetic_energy",
                "gravitational_potential_energy",
            ],
            "title": "optional string override",
            "subtitle": "optional string subtitle",
            "equation_text": "optional equation string override",
            "variable_notes": [{"symbol": "string", "meaning": "string"}],
            "secondary_equations": ["optional list of related equation strings"],
            "show_units_hint": "optional boolean, defaults to true",
        },
    },
    "particle_physics_visual": {
        "description": "Deterministic SVG visuals for particle physics overviews, hadrons, decay chains, and collisions.",
        "concept_aliases": [
            "particle_physics_visual",
            "particle_physics",
            "standard_model",
            "hadron_diagram",
        ],
        "template_aliases": [
            "particle_physics_visual",
        ],
        "meta_contract": {
            "visual_type": [
                "standard_model_overview",
                "hadron_composition",
                "decay_chain",
                "collision_event",
            ],
            "title": "optional string override",
            "subtitle": "optional string subtitle",
            "hadron_type": "optional hadron name, typically proton or neutron",
            "parent_particle": "optional parent particle label for decay chain",
            "decay_products": ["optional decay product labels"],
        },
    },
    "quantum_physics_visual": {
        "description": "Deterministic SVG visuals for energy levels, tunneling, probability, and double-slit concepts.",
        "concept_aliases": [
            "quantum_physics_visual",
            "quantum_visual",
            "quantum_diagram",
        ],
        "template_aliases": [
            "quantum_physics_visual",
        ],
        "meta_contract": {
            "visual_type": [
                "energy_levels",
                "tunneling_barrier",
                "probability_density",
                "double_slit_pattern",
            ],
            "title": "optional string override",
            "subtitle": "optional string subtitle",
            "level_count": "optional integer from 2 to 6 for energy-level diagrams",
        },
    },
    "radioactivity_radiation_visual": {
        "description": "Deterministic SVG visuals for penetration, half-life, decay chains, and electromagnetic spectrum lessons.",
        "concept_aliases": [
            "radioactivity_radiation_visual",
            "radioactivity_visual",
            "radiation_visual",
            "half_life_diagram",
        ],
        "template_aliases": [
            "radioactivity_radiation_visual",
        ],
        "meta_contract": {
            "visual_type": [
                "alpha_beta_gamma_penetration",
                "half_life_curve",
                "nuclear_decay_chain",
                "electromagnetic_spectrum",
            ],
            "title": "optional string override",
            "subtitle": "optional string subtitle",
            "half_life": "optional positive number for half-life curve",
            "initial_amount": "optional positive starting amount for half-life curve",
            "parent_nuclide": "optional parent nuclide label",
            "daughter_nuclide": "optional daughter nuclide label",
        },
    },
}


@dataclass
class DiagramRequest:
    asset_id: str
    phase_key: str
    concept: str
    description: str
    title: str = ""
    template: str = "auto"
    width: int = 1280
    height: int = 720
    meta: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnimationRequest:
    asset_id: str
    phase_key: str
    concept: str
    description: str
    title: str = ""
    duration_sec: int = 8
    engine: str = "svg_html"


@dataclass
class SimulationRequest:
    asset_id: str
    phase_key: str
    lab_id: str
    concept: str
    description: str
    title: str = ""
    engine: str = "p5"


@dataclass
class LessonAssetRequests:
    diagrams: List[DiagramRequest] = field(default_factory=list)
    animations: List[AnimationRequest] = field(default_factory=list)
    simulation: SimulationRequest | None = None

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "LessonAssetRequests":
        diagrams = [DiagramRequest(**item) for item in payload.get("diagrams") or []]
        animations = [AnimationRequest(**item) for item in payload.get("animations") or []]
        simulation_payload = payload.get("simulation")
        simulation = SimulationRequest(**simulation_payload) if isinstance(simulation_payload, dict) else None
        return cls(diagrams=diagrams, animations=animations, simulation=simulation)


@dataclass
class LessonSpec:
    lesson_id: str
    module_id: str
    title: str
    phases: Dict[str, Any]
    asset_requests: LessonAssetRequests = field(default_factory=LessonAssetRequests)

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "LessonSpec":
        return cls(
            lesson_id=str(payload["lesson_id"]),
            module_id=str(payload["module_id"]),
            title=str(payload.get("title") or payload["lesson_id"]),
            phases=dict(payload.get("phases") or {}),
            asset_requests=LessonAssetRequests.from_dict(payload.get("asset_requests") or {}),
        )

    @classmethod
    def load(cls, path: str | Path) -> "LessonSpec":
        raw = json.loads(Path(path).read_text(encoding="utf-8-sig"))
        return cls.from_dict(raw)

    def dump(self, path: str | Path) -> None:
        Path(path).write_text(
            json.dumps(asdict(self), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )


@dataclass
class GeneratedAsset:
    asset_id: str
    kind: str
    phase_key: str
    title: str
    concept: str
    storage_path: str
    public_url: str
    mime_type: str
    provider: str
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CompiledLessonPackage:
    lesson_id: str
    module_id: str
    title: str
    phases: Dict[str, Any]
    generated_assets: Dict[str, Any]
    lesson_patch: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def dump(self, path: str | Path) -> None:
        Path(path).write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
