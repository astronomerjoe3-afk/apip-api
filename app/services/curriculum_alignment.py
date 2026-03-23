from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict

from app.common import normalize_module_id


_ALIGNMENT: Dict[str, Dict[str, Any]] = {
    "F1": {"curriculum_version": "refined_curriculum_2026", "phase": "phase_1_foundations", "revised_slot": "F1", "revised_title": "Scientific Measurement and Representation", "alignment_role": "exact_match", "analogy_family": "Measurement and representation bridge"},
    "F2": {"curriculum_version": "refined_curriculum_2026", "phase": "phase_1_foundations", "revised_slot": "F2", "revised_title": "Motion, Forces and Energy", "alignment_role": "exact_match", "analogy_family": "Foundations motion-force-energy model"},
    "F3": {"curriculum_version": "refined_curriculum_2026", "phase": "phase_1_foundations", "revised_slot": "F3", "revised_title": "Matter, Particles and Thermal Behaviour", "alignment_role": "exact_match", "analogy_family": "Foundations particle-and-thermal model"},
    "F4": {"curriculum_version": "refined_curriculum_2026", "phase": "phase_1_foundations", "revised_slot": "F4", "revised_title": "Waves, Light and Electricity", "alignment_role": "exact_match", "analogy_family": "Foundations waves-light-electricity model"},
    "F5": {"curriculum_version": "refined_curriculum_2026", "phase": "phase_1_foundations", "revised_slot": "F5", "revised_title": "Observable Earth and Sky", "alignment_role": "exact_match", "analogy_family": "Lantern-Ring Skycourt Model"},
    "M1": {"curriculum_version": "refined_curriculum_2026", "phase": "phase_2_core_physics", "revised_slot": "M1", "revised_title": "Motion and Kinematics", "alignment_role": "exact_match", "analogy_family": "Quest-Log Model of Motion"},
    "M2": {"curriculum_version": "refined_curriculum_2026", "phase": "phase_2_core_physics", "revised_slot": "M2", "revised_title": "Forces and Equilibrium", "alignment_role": "exact_match", "analogy_family": "Thruster-Deck Model of Forces"},
    "M3": {"curriculum_version": "refined_curriculum_2026", "phase": "phase_2_core_physics", "revised_slot": "M3", "revised_title": "Momentum, Work, Energy and Power", "alignment_role": "exact_match", "analogy_family": "Cargo-Launch Ledger Model"},
    "M4": {"curriculum_version": "refined_curriculum_2026", "phase": "phase_2_core_physics", "revised_slot": "M4", "revised_title": "Materials, Density and Pressure", "alignment_role": "exact_match", "analogy_family": "Load-Test Yard Model"},
    "M5": {"curriculum_version": "refined_curriculum_2026", "phase": "phase_2_core_physics", "revised_slot": "M5", "revised_title": "Particle Model and Internal Energy", "alignment_role": "exact_match", "analogy_family": "Pulse-Plaza Forge Model"},
    "M6": {"curriculum_version": "refined_curriculum_2026", "phase": "phase_2_core_physics", "revised_slot": "M6", "revised_title": "Thermal Transfer and Gas Behaviour", "alignment_role": "exact_match", "analogy_family": "Forge-Chamber Model of Heat and Gas"},
    "M7": {"curriculum_version": "refined_curriculum_2026", "phase": "phase_2_core_physics", "revised_slot": "M7", "revised_title": "Waves and Vibrations", "alignment_role": "exact_match", "analogy_family": "Signal-Stadium Model"},
    "M8": {"curriculum_version": "refined_curriculum_2026", "phase": "phase_2_core_physics", "revised_slot": "M8", "revised_title": "Light and Optics", "alignment_role": "exact_match", "analogy_family": "Glow-Route Model of Light"},
    "M9": {"curriculum_version": "refined_curriculum_2026", "phase": "phase_2_core_physics", "revised_slot": "M9", "revised_title": "Electrical Quantities and Circuits", "alignment_role": "exact_match", "analogy_family": "Carrier-Loop Switchyard Model"},
    "M10": {"curriculum_version": "refined_curriculum_2026", "phase": "phase_2_core_physics", "revised_slot": "M10", "revised_title": "Magnetism and Electromagnetic Effects", "alignment_role": "exact_match", "analogy_family": "Field-Weave Model of Magnetism and Electromagnetic Effects"},
    "M11": {"curriculum_version": "refined_curriculum_2026", "phase": "phase_2_core_physics", "revised_slot": "M11", "revised_title": "Atomic Structure and Radioactivity", "alignment_role": "exact_match", "analogy_family": "Core-Vault Model of Radioactivity"},
    "M12": {"curriculum_version": "refined_curriculum_2026", "phase": "phase_2_core_physics", "revised_slot": "M12", "revised_title": "Nuclear Energy and Applications", "alignment_role": "exact_match", "analogy_family": "Core-Forge Reactor Model"},
    "M13": {"curriculum_version": "refined_curriculum_2026", "phase": "phase_2_core_physics", "revised_slot": "M13", "revised_title": "Earth and the Solar System", "alignment_role": "exact_match", "analogy_family": "Lantern-Ring Model of the Solar System"},
    "M14": {"curriculum_version": "refined_curriculum_2026", "phase": "phase_2_core_physics", "revised_slot": "M14", "revised_title": "Stars and the Universe", "alignment_role": "exact_match", "analogy_family": "Beacon-City Stretchmap Model of the Universe"},
    "A1": {"curriculum_version": "refined_curriculum_2026", "phase": "phase_3_advanced", "revised_slot": "A1", "revised_title": "Matter, Radiation and Particles", "alignment_role": "pending_catalog_expansion", "analogy_family": "Particle-Port Exchange Model"},
    "A2": {"curriculum_version": "refined_curriculum_2026", "phase": "phase_3_advanced", "revised_slot": "A2", "revised_title": "Quantum Phenomena and Atomic Spectra", "alignment_role": "pending_catalog_expansion", "analogy_family": "Ladder-Gate Packet Model of Quantum Atoms"},
    "A3": {"curriculum_version": "refined_curriculum_2026", "phase": "phase_3_advanced", "revised_slot": "A3", "revised_title": "Advanced Waves and Optics", "alignment_role": "pending_catalog_expansion", "analogy_family": "Phase-Loom Model of Advanced Waves"},
    "A4": {"curriculum_version": "refined_curriculum_2026", "phase": "phase_3_advanced", "revised_slot": "A4", "revised_title": "Advanced Mechanics and Materials", "alignment_role": "pending_catalog_expansion", "analogy_family": "Vector-Rig Model of Mechanics and Materials"},
    "A5": {"curriculum_version": "refined_curriculum_2026", "phase": "phase_3_advanced", "revised_slot": "A5", "revised_title": "Oscillations", "alignment_role": "pending_catalog_expansion", "analogy_family": "Swing-Return Model of Oscillations"},
}


def curriculum_alignment_for_module(module_id: Any) -> Dict[str, Any]:
    normalized = normalize_module_id(module_id)
    if not normalized:
        return {}
    return deepcopy(_ALIGNMENT.get(normalized, {}))


def apply_module_curriculum_alignment(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return payload
    normalized = normalize_module_id(payload.get("id") or payload.get("module_id"))
    if not normalized:
        return payload
    alignment = curriculum_alignment_for_module(normalized)
    if not alignment:
        return payload
    updated = deepcopy(payload)
    updated["curriculum_alignment"] = alignment
    return updated
