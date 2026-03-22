from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List, Sequence


def _tw(term: str, meaning: str, why_it_matters: str) -> Dict[str, str]:
    return {"term": term, "meaning": meaning, "why_it_matters": why_it_matters}


MODULE_CODE_ALIASES = {
    "MA1": "A1",
    "MA2": "A2",
    "MA3": "A3",
    "MA4": "A4",
    "MA5": "A5",
}


DEFAULT_TECHNICAL_WORDS_BY_MODULE: Dict[str, List[Dict[str, str]]] = {
    "F1": [
        _tw("Unit", "A unit is the agreed size used to measure a quantity.", "A number without a unit does not fully describe a measurement."),
        _tw("Scalar", "A scalar quantity has size only, with no direction attached.", "It helps separate plain amounts from direction-based quantities."),
        _tw("Vector", "A vector quantity has both size and direction.", "Direction changes the meaning, so vectors cannot be treated like scalars."),
        _tw("Density", "Density is the mass packed into each unit of volume.", "It compares how much matter is in a given amount of space."),
    ],
    "F2": [
        _tw("Distance", "Distance is the total path length travelled, without direction.", "It tells how much ground was covered, not where the motion finished."),
        _tw("Displacement", "Displacement is the straight-line change in position from start to finish, including direction.", "It keeps the final-position story separate from the path-length story."),
        _tw("Velocity", "Velocity is speed in a stated direction.", "It matters because acceleration depends on changes in velocity."),
        _tw("Acceleration", "Acceleration is the rate at which velocity changes.", "It can come from changing speed, direction, or both."),
    ],
    "F3": [
        _tw("Energy store", "An energy store is a way energy is held in a system.", "It helps learners track where the energy is."),
        _tw("Work done", "Work done is energy transferred when a force acts through a distance.", "It links force-and-motion stories to energy change."),
        _tw("Power", "Power is the rate of energy transfer.", "It tells how quickly energy is being transferred."),
        _tw("Conservation of energy", "Conservation of energy means total energy stays accounted for overall.", "It stops students from saying energy is destroyed."),
    ],
    "F4": [
        _tw("Wave", "A wave is a travelling disturbance that transfers energy without the whole medium moving with it.", "It is the anchor idea behind reflection and refraction."),
        _tw("Wavelength", "Wavelength is the distance between matching points on neighbouring waves.", "It links pattern spacing to wave behaviour."),
        _tw("Current", "Current is the rate of charge flow in a circuit.", "It is not the same as voltage or stored energy."),
        _tw("Voltage", "Voltage is the energy transferred per unit charge between two points.", "It tells what each charge gets, not how many charges pass."),
    ],
    "M1": [
        _tw("Distance-time graph", "A distance-time graph shows how total distance changes with time.", "Its slope tells speed, not acceleration."),
        _tw("Speed-time graph", "A speed-time graph shows how speed changes with time.", "Its slope and area answer different motion questions."),
        _tw("Gradient", "The gradient is the steepness of a graph line.", "Its meaning depends on the axes."),
        _tw("Constant acceleration", "Constant acceleration means velocity changes by equal amounts in equal times.", "It is the condition behind the standard motion equations."),
    ],
    "M2": [
        _tw("Resultant force", "The resultant force is the combined overall force after all forces are added with direction.", "Acceleration depends on the resultant, not one isolated force."),
        _tw("Momentum", "Momentum is the quantity of motion given by mass multiplied by velocity.", "It is useful in collisions and explosions."),
        _tw("Moment", "A moment is the turning effect of a force about a pivot.", "It depends on both force and perpendicular distance."),
        _tw("Centre of mass", "The centre of mass is the point where an object's mass can often be treated as concentrated.", "It helps explain balance and stability."),
    ],
    "M3": [
        _tw("Kinetic energy", "Kinetic energy is the energy store associated with motion.", "It rises strongly when speed increases."),
        _tw("Gravitational potential energy", "Gravitational potential energy is the energy store associated with position in a gravitational field.", "Lifting an object increases this store."),
        _tw("Power", "Power is the rate of energy transfer or work done.", "It tells how quickly the transfer happens."),
        _tw("Efficiency", "Efficiency is the fraction of the input that becomes useful output.", "It separates useful transfer from wasted transfer."),
    ],
    "M4": [
        _tw("Pressure", "Pressure is force per unit area.", "It tells how concentrated a push is."),
        _tw("Density", "Density is mass per unit volume.", "In liquids, denser fluids give larger pressure increases with depth."),
        _tw("Depth", "Depth is the distance below the liquid surface.", "Greater depth means more liquid above and greater pressure."),
        _tw("Atmospheric pressure", "Atmospheric pressure is the pressure caused by the weight of the air above a surface.", "It explains why air can press on us and on liquids."),
    ],
    "M5": [
        _tw("Particle", "A particle is one tiny unit of matter, such as an atom or molecule.", "The particle model explains bulk behaviour from tiny moving units."),
        _tw("Brownian motion", "Brownian motion is the random zigzag movement of visible particles caused by uneven collisions with invisible molecules.", "It provides evidence that particles are in constant motion."),
        _tw("Temperature", "Temperature tells how energetic the average particle motion is.", "It is about average particle energy, not the total energy of the system."),
        _tw("Internal energy", "Internal energy is the total kinetic and potential energy of all the particles in a system.", "Two systems can share a temperature but have different internal energies."),
    ],
    "M6": [
        _tw("Specific heat capacity", "Specific heat capacity is the energy needed to raise the temperature of one kilogram of a substance by one degree.", "It explains why some materials warm more slowly than others."),
        _tw("Latent heat", "Latent heat is energy transferred during a change of state without a temperature change.", "It shows energy can loosen particle bonds instead of raising temperature."),
        _tw("Conduction", "Conduction is thermal energy transfer through a material by particle or electron interactions.", "It explains direct-contact thermal transfer."),
        _tw("Convection", "Convection is thermal energy transfer by the bulk movement of a fluid.", "Warmer, less dense fluid can rise and carry energy with it."),
    ],
    "M7": [
        _tw("Transverse wave", "A transverse wave has local disturbance perpendicular to the direction of travel.", "Wave type depends on the relation between local motion and propagation."),
        _tw("Longitudinal wave", "A longitudinal wave has local disturbance parallel to the direction of travel.", "It contrasts with transverse motion."),
        _tw("Frequency", "Frequency is the number of wave cycles each second.", "It is set by the source."),
        _tw("Diffraction", "Diffraction is the bending or spreading of a wave around an opening or obstacle.", "It becomes more noticeable when the opening is comparable to the wavelength."),
    ],
    "M8": [
        _tw("Normal", "The normal is the line drawn perpendicular to a surface at the point where a ray hits.", "Angles of incidence and reflection are measured from it."),
        _tw("Refraction", "Refraction is the change in direction caused when light changes speed in a new medium.", "It is a turning-by-speed-change story, not just a bend to memorize."),
        _tw("Virtual image", "A virtual image is an apparent image where light only seems to come from a point.", "It is found using backward extensions, not real ray crossings."),
        _tw("Critical angle", "The critical angle is the last angle that still allows a refracted ray to escape before total internal reflection begins.", "It is the boundary limit between escape and lock-bounce."),
    ],
    "M9": [
        _tw("Sound wave", "A sound wave is a longitudinal wave made of compressions and rarefactions in a medium.", "It links hearing to particle vibration and wave travel."),
        _tw("Frequency", "Frequency is the number of vibrations each second.", "It helps explain pitch."),
        _tw("Amplitude", "Amplitude is the maximum size of the oscillation.", "It helps explain loudness."),
        _tw("Ultrasound", "Ultrasound is sound with a frequency above the human hearing range.", "It is useful for imaging and sensing because of how it reflects."),
    ],
    "M10": [
        _tw("Charge", "Charge is the conserved carrier quantity moving around the circuit.", "It is the moving stuff, not the same thing as current."),
        _tw("Current", "Current is the rate of charge flow past a point.", "It tells how many carriers pass each second."),
        _tw("Voltage", "Voltage is the energy transferred per unit charge.", "It is the boost given to each carrier, not the current itself."),
        _tw("Resistance", "Resistance is how strongly a path limits the current for a given voltage.", "It belongs to the route, not to the battery."),
    ],
    "M11": [
        _tw("Series circuit", "A series circuit has one path, so the same current passes through each component in that path.", "One open component can stop the whole chain."),
        _tw("Parallel circuit", "A parallel circuit has branches connected between the same two junctions.", "Each branch shares the same potential difference while current can split."),
        _tw("Equivalent resistance", "Equivalent resistance is the single resistance that would have the same overall effect as the whole network.", "It simplifies mixed networks step by step."),
        _tw("Short circuit", "A short circuit is an unintended very-low-resistance path that allows a dangerously large current.", "It can overheat wires quickly and must be interrupted by protection."),
    ],
    "M12": [
        _tw("Magnetic field", "A magnetic field is the region where a magnetic force would act.", "It is the invisible structure behind many magnetic effects."),
        _tw("Electromagnet", "An electromagnet is a magnet created by electric current, often using a coil and an iron core.", "It links electricity and magnetism in a controllable way."),
        _tw("Electromagnetic induction", "Electromagnetic induction is the creation of an emf when magnetic flux changes.", "It is the central idea behind generators and transformers."),
        _tw("Transformer", "A transformer is a device that uses induction between coils to change voltage in alternating-current systems.", "It is essential for efficient power transmission."),
    ],
    "M13": [
        _tw("Isotope", "Isotopes are atoms of the same element with the same number of protons but different numbers of neutrons.", "Some isotopes are stable and some are radioactive."),
        _tw("Radioactive decay", "Radioactive decay is the spontaneous change of an unstable nucleus into a more stable form.", "It is random for one nucleus but predictable for large numbers."),
        _tw("Half-life", "Half-life is the time taken for the number of undecayed nuclei, or the activity, to fall to half its value.", "It turns random decay into a measurable pattern."),
        _tw("Ionisation", "Ionisation is the process of removing or adding electrons so atoms become charged.", "It is central to radiation hazard and detection."),
    ],
    "M14": [
        _tw("Orbit", "An orbit is the curved path one body follows around another because of gravity.", "It explains planetary years, moon motion, and changing viewpoints."),
        _tw("Axis", "An axis is the imaginary line about which an object rotates.", "Tilt and rotation about the axis shape many astronomy patterns."),
        _tw("Moon phase", "A moon phase is the visible shape of the lit part of the Moon as seen from Earth.", "Phases come from viewpoint change, not ordinary eclipses."),
        _tw("Eclipse", "An eclipse happens when one astronomical body moves into the shadow of another or blocks its light.", "It is a special alignment event, not the normal explanation for phases."),
    ],
    "M15": [
        _tw("Star", "A star is a self-luminous ball of gas powered by nuclear fusion in its core.", "It makes stars different from planets that only reflect light."),
        _tw("Galaxy", "A galaxy is a huge gravity-bound collection of stars, gas, dust, and dark matter.", "It is far larger than a star system but smaller than the whole universe."),
        _tw("Light-year", "A light-year is a distance: the distance light travels in one year.", "The word year is part of the definition, but the quantity measured is distance."),
        _tw("Redshift", "Redshift is the increase in observed wavelength compared with the emitted wavelength.", "It is evidence in the expansion story."),
    ],
    "A1": [
        _tw("Projectile motion", "Projectile motion is two-dimensional motion under gravity after launch.", "It helps break a curved path into simpler component stories."),
        _tw("Horizontal velocity", "Horizontal velocity is the component of velocity parallel to the chosen horizontal axis.", "In simple projectile motion without air resistance, it stays constant."),
        _tw("Centripetal force", "Centripetal force is the inward resultant force needed to keep an object moving in a circle.", "It is the inward role of the resultant, not a separate extra force."),
        _tw("Gravitational field", "A gravitational field is the region where masses experience gravitational force.", "It supports orbital and field-based reasoning."),
    ],
    "A2": [
        _tw("Electric field", "An electric field is the force per unit positive charge at a location.", "It belongs to the location, not to the test charge itself."),
        _tw("Electric potential", "Electric potential is electric potential energy per unit charge at a point.", "It is the height map behind voltage."),
        _tw("Capacitance", "Capacitance is the charge stored per unit potential difference.", "It tells how much charge a capacitor can hold for each volt."),
        _tw("Kirchhoff's voltage law", "Kirchhoff's voltage law states that the algebraic sum of potential rises and drops around a closed loop is zero.", "It is energy conservation written in loop language."),
    ],
    "A3": [
        _tw("Magnetic flux", "Magnetic flux measures how much magnetic field passes through an area.", "Changing flux is central to induction."),
        _tw("Flux linkage", "Flux linkage is the magnetic flux multiplied by the number of turns in a coil.", "It helps describe induction in multi-turn coils."),
        _tw("Alternating current", "Alternating current changes direction periodically.", "It is the form of current needed for transformers."),
        _tw("RMS value", "The RMS value of an alternating current or voltage is the steady DC-equivalent value for power effects.", "It lets AC values be compared fairly with DC effects."),
    ],
    "A4": [
        _tw("Ideal gas", "An ideal gas is a simplified model gas whose particles have negligible volume and no intermolecular forces except during collisions.", "It gives a clean starting point for gas-law reasoning."),
        _tw("Pressure", "Gas pressure comes from particle collisions with container walls.", "It ties the macroscopic gas story to microscopic particle behaviour."),
        _tw("Kinetic theory", "Kinetic theory explains gas behaviour in terms of tiny particles moving randomly and colliding.", "It links particle ideas to gas laws."),
        _tw("Entropy", "Entropy is a measure related to how spread out energy is and how many microscopic arrangements are possible.", "It adds direction and probability ideas to thermal change."),
    ],
    "A5": [
        _tw("Photoelectric effect", "The photoelectric effect is the emission of electrons from a surface when light of high enough frequency shines on it.", "It shows that light transfers energy in packets."),
        _tw("Photon", "A photon is a packet of electromagnetic energy.", "It supports the particle side of the light model."),
        _tw("Wave-particle duality", "Wave-particle duality is the idea that quantum objects show both wave-like and particle-like behaviour.", "It helps learners hold two valid descriptions together."),
        _tw("Time dilation", "Time dilation is the effect in relativity where moving clocks are measured to run slower than stationary ones.", "It is one of the key shifts away from everyday intuition."),
    ],
}


def canonical_module_code(code: str) -> str:
    normalized = str(code or "").strip().upper()
    return MODULE_CODE_ALIASES.get(normalized, normalized)


def module_code_from_lesson(lesson: Dict[str, Any]) -> str:
    lesson_code = str(lesson.get("lesson_id") or lesson.get("id") or lesson.get("module_id") or lesson.get("moduleId") or "").strip()
    if "_" in lesson_code:
        lesson_code = lesson_code.split("_", 1)[0]
    return canonical_module_code(lesson_code)


def default_technical_words_for_module(module_code: str) -> List[Dict[str, str]]:
    return deepcopy(DEFAULT_TECHNICAL_WORDS_BY_MODULE.get(canonical_module_code(module_code), []))


def ensure_minimum_technical_words(
    existing: Sequence[Dict[str, Any]] | None,
    module_code: str,
    *,
    minimum: int = 4,
    maximum: int = 6,
) -> List[Dict[str, str]]:
    merged: List[Dict[str, str]] = []
    seen = set()

    for source in list(existing or []) + default_technical_words_for_module(module_code):
        term = str(source.get("term") or "").strip()
        meaning = str(source.get("meaning") or "").strip()
        if not term or not meaning:
            continue
        key = term.lower()
        if key in seen:
            continue
        seen.add(key)
        merged.append(
            {
                "term": term,
                "meaning": meaning,
                "why_it_matters": str(source.get("why_it_matters") or source.get("whyItMatters") or "").strip(),
            }
        )
        if len(merged) >= maximum:
            break

    if len(merged) >= minimum:
        return merged
    return merged
