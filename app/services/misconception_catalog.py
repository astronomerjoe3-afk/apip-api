from __future__ import annotations

from typing import Dict, List, Optional


MisconceptionSummary = Dict[str, str]


EXACT_SUMMARIES: Dict[str, Dict[str, str]] = {
    "vector_scalar_confusion": {
        "title": "Vector vs scalar direction logic",
        "diagnosis": "The answer is mixing up quantity size with quantity direction, so two related ideas are being treated as the same thing.",
        "repair": "Name the quantity first, then ask whether direction changes its meaning. If direction is essential, the quantity is acting like a vector.",
        "notice_next": "Watch for unit pairs that look similar but mean different physics once direction matters.",
    },
    "distance_displacement_confusion": {
        "title": "Distance vs displacement reasoning",
        "diagnosis": "The answer is treating total journey length as the same idea as overall change in position.",
        "repair": "Track the full path for distance, but compare start and finish position for displacement.",
        "notice_next": "When a journey includes turning back, distance and displacement usually separate sharply.",
    },
    "velocity_direction_confusion": {
        "title": "Velocity needs direction",
        "diagnosis": "The answer is reading velocity like speed and dropping the directional part of the motion.",
        "repair": "Keep speed for size-only motion and velocity for speed with direction attached.",
        "notice_next": "If the prompt asks about east, west, up, down, or reversal, direction is part of the physics.",
    },
    "acceleration_sign_confusion": {
        "title": "Acceleration sign and direction",
        "diagnosis": "The answer is reading negative acceleration as 'slowing down' automatically instead of checking the chosen direction convention.",
        "repair": "State the positive direction first, then decide whether the acceleration points with it or against it.",
        "notice_next": "Negative acceleration means opposite to the chosen positive direction, not automatically less speed.",
    },
    "distance_time_graph_error": {
        "title": "Distance-time graph meaning",
        "diagnosis": "The answer is matching the graph by appearance instead of translating the axes and the segment meaning into a motion story.",
        "repair": "Read one segment at a time. Height gives distance from the reference point, and slope tells how that distance changes.",
        "notice_next": "A flat line means time still passes while distance stays constant.",
    },
    "velocity_time_graph_error": {
        "title": "Velocity-time graph meaning",
        "diagnosis": "The answer is mixing up graph height, graph slope, and graph area on a velocity-time graph.",
        "repair": "Height gives velocity at that instant, slope gives acceleration, and area gives change in displacement.",
        "notice_next": "Name the axes first before deciding what the graph feature means.",
    },
    "balanced_force_motion_confusion": {
        "title": "Balanced force and motion change",
        "diagnosis": "The answer is assuming balanced forces mean no motion instead of no change in motion.",
        "repair": "Use the resultant first. A zero resultant means zero acceleration, so the current velocity can stay unchanged.",
        "notice_next": "Keep 'no change in velocity' separate from 'velocity equals zero'.",
    },
    "resultant_force_error": {
        "title": "Resultant force reasoning",
        "diagnosis": "The answer is focusing on the number or appearance of forces instead of the single combined force on one object.",
        "repair": "Collapse the force story to one object and one resultant before you predict what the motion does next.",
        "notice_next": "Counted arrows do not matter as much as the final force balance on the object.",
    },
    "inertia_force_confusion": {
        "title": "Inertia vs force",
        "diagnosis": "The answer is treating inertia as if it were an extra force acting on the object.",
        "repair": "Keep inertia as the tendency to resist change in velocity, while forces are the interactions that can cause that change.",
        "notice_next": "If the question is about resisting change, ask whether it is describing a property or an interaction.",
    },
    "fma_relationship_error": {
        "title": "Force, mass, and acceleration link",
        "diagnosis": "The answer is not keeping the proportional relationship in F = ma tied to the same object and the same resultant force.",
        "repair": "Name the resultant force, then compare how mass and acceleration change for that object only.",
        "notice_next": "A larger mass changes acceleration only when you are comparing the same resultant force.",
    },
    "work_energy_transfer_confusion": {
        "title": "Work as an energy hand-off",
        "diagnosis": "The answer is not keeping work tied to the transfer of energy through a force acting over a distance.",
        "repair": "Describe the hand-off first: force through distance transfers energy into or out of a store.",
        "notice_next": "If the question mentions pushing through a distance, check whether it is really asking about energy transfer.",
    },
    "gravitational_potential_energy_error": {
        "title": "Gravitational store factors",
        "diagnosis": "The answer is dropping one of the three key factors in gravitational store: mass, field strength, or height.",
        "repair": "Keep all three factors visible and change only one at a time when comparing situations.",
        "notice_next": "If two situations keep height the same, field strength can still change the store.",
    },
    "kinetic_energy_relationship_error": {
        "title": "Kinetic energy relationship",
        "diagnosis": "The answer is underestimating how strongly speed changes the motion store.",
        "repair": "Compare mass and speed carefully, then remember that kinetic energy grows with the square of speed.",
        "notice_next": "Doubling speed has a much bigger effect than doubling mass.",
    },
    "efficiency_calculation_error": {
        "title": "Efficiency and useful fraction",
        "diagnosis": "The answer is treating the total input as if it all stays useful.",
        "repair": "Separate the full input from the useful output, then compare the useful fraction to the total.",
        "notice_next": "A faster machine is not automatically a more efficient one.",
    },
    "power_rate_confusion": {
        "title": "Power as rate",
        "diagnosis": "The answer is mixing up total energy transferred with how fast that transfer happens.",
        "repair": "Keep the total transfer and the transfer time separate, then compare the rate.",
        "notice_next": "Power changes when the same energy moves in a different time.",
    },
    "momentum_vector_confusion": {
        "title": "Momentum direction logic",
        "diagnosis": "The answer is treating momentum as size only and dropping its directional nature.",
        "repair": "Track momentum with both magnitude and direction, just as you would for velocity.",
        "notice_next": "Collisions and reversals usually punish momentum questions that ignore direction.",
    },
    "momentum_conservation_confusion": {
        "title": "Momentum conservation logic",
        "diagnosis": "The answer is applying conservation to one object instead of the full system or ignoring how momenta balance together.",
        "repair": "Choose the system boundary first, then compare total momentum before and after within that same system.",
        "notice_next": "Conservation claims are strongest when you can name the whole interacting system explicitly.",
    },
    "collision_safety_reasoning_confusion": {
        "title": "Collision safety reasoning",
        "diagnosis": "The answer is skipping the change-in-time idea that explains why safety features reduce force on the body.",
        "repair": "Connect the same change in momentum to a longer stopping time, then to a smaller average force.",
        "notice_next": "Safety questions often hinge on impulse spread over time, not on removing momentum entirely.",
    },
    "braking_energy_comparison_confusion": {
        "title": "Braking and energy comparison",
        "diagnosis": "The answer is not keeping the energy change and the speed comparison tied together through the whole stop.",
        "repair": "Start from the motion energy before braking, then compare how much must be transferred out during the stop.",
        "notice_next": "Braking questions often reward comparing initial motion stores before thinking about stopping force.",
    },
    "unit_quantity_mismatch": {
        "title": "Unit-to-quantity mismatch",
        "diagnosis": "The answer is pairing a quantity with the wrong standard unit.",
        "repair": "Name the physical quantity first, then match it to the agreed unit rather than a familiar-looking symbol.",
        "notice_next": "Related quantities can share words in the prompt but still need different units.",
    },
    "unit_as_label_only": {
        "title": "Units as scale, not just labels",
        "diagnosis": "The answer is treating the unit like a label instead of a scale that changes the size of the number.",
        "repair": "State the conversion factor explicitly so the new unit stays tied to the same physical quantity.",
        "notice_next": "Prefixes only make sense when the factor linking the two scales is clear.",
    },
    "prefix_scale_error": {
        "title": "Prefix and scale conversion",
        "diagnosis": "The answer is moving the decimal without naming the power-of-ten factor underneath it.",
        "repair": "Write the factor first, then convert the number using that factor.",
        "notice_next": "The safest conversion is the one you can justify with the unit scale, not just a decimal trick.",
    },
    "precision_vs_accuracy": {
        "title": "Precision vs accuracy",
        "diagnosis": "The answer is mixing up closeness to the accepted value with closeness between repeated results.",
        "repair": "Use accuracy for closeness to the accepted value and precision for spread between repeated results.",
        "notice_next": "A result can be precise without being accurate if the readings cluster around the wrong value.",
    },
    "random_vs_systematic_error": {
        "title": "Random vs systematic error",
        "diagnosis": "The answer is not separating scatter in the readings from a consistent bias in the setup.",
        "repair": "Random error changes the spread. Systematic error shifts the whole set in one direction.",
        "notice_next": "If the same bias appears every time, it is probably not a random effect.",
    },
    "precision_trust_error": {
        "title": "Measurement trust and uncertainty",
        "diagnosis": "The answer is reporting a value without checking whether the scale and uncertainty justify that confidence.",
        "repair": "Read the instrument carefully, then state the value only to the precision the scale can support.",
        "notice_next": "Trustworthy measurements are limited by the instrument, not by how many digits you want to write.",
    },
    "flat_line_time_confusion": {
        "title": "Flat line and passing time",
        "diagnosis": "The answer is reading a flat segment as if time stopped instead of distance staying constant.",
        "repair": "Keep time moving along the horizontal axis and let the unchanged vertical value tell you the object is stationary.",
        "notice_next": "Flat does not mean blank; it means the tracked quantity stayed fixed while time continued.",
    },
    "height_vs_slope_confusion": {
        "title": "Graph height vs slope",
        "diagnosis": "The answer is mixing the value shown by the graph height with the change rate shown by the slope.",
        "repair": "Ask whether the question wants the vertical-axis value now or how quickly that value is changing.",
        "notice_next": "Height and steepness can both matter, but they rarely mean the same thing.",
    },
    "slope_meaning_confusion": {
        "title": "Slope depends on the axes",
        "diagnosis": "The answer is assuming the same steepness always means the same physics quantity.",
        "repair": "Name the axes before naming the slope. The graph family decides what the steepness represents.",
        "notice_next": "The geometry can match while the physics meaning changes completely.",
    },
    "area_under_graph_confusion": {
        "title": "Area under the graph meaning",
        "diagnosis": "The answer is treating the line itself as the total quantity instead of the shaded region beneath it.",
        "repair": "Use the units made by the vertical and horizontal axes together to decide why the area matters.",
        "notice_next": "Area questions reward checking the combined units, not just the shape.",
    },
    "third_law_cancellation": {
        "title": "Third-law pair cancellation",
        "diagnosis": "The answer is cancelling equal and opposite forces that act on different objects.",
        "repair": "Choose one object first, then keep only the forces acting on that object in the free-body story.",
        "notice_next": "Equal and opposite does not mean cancel if the forces belong to different objects.",
    },
    "zero_resultant_zero_motion": {
        "title": "Zero resultant vs zero motion",
        "diagnosis": "The answer is turning 'no change in velocity' into 'velocity must be zero.'",
        "repair": "Use the resultant to decide acceleration, then ask what the current velocity was already doing.",
        "notice_next": "Balanced forces freeze the change, not necessarily the motion.",
    },
    "torque_reach_confusion": {
        "title": "Torque depends on reach",
        "diagnosis": "The answer is focusing on force size alone and ignoring how far the force acts from the pivot.",
        "repair": "Compare the perpendicular distance from the pivot before you compare turning effect.",
        "notice_next": "A large force through the pivot can still produce no turning effect.",
    },
    "stability_line_of_action": {
        "title": "Stability follows the line of action",
        "diagnosis": "The answer is predicting tipping from size or mass alone without checking where the weight line lands.",
        "repair": "Track the line of action relative to the support base before you predict whether the system tips.",
        "notice_next": "Stability questions are usually decided by position, not by one headline number.",
    },
    "energy_leak_accounting": {
        "title": "Leak and useful gain accounting",
        "diagnosis": "The answer is letting useful output ignore the energy that leaked away.",
        "repair": "Balance the input as useful gain plus leak before you place the useful part into stores.",
        "notice_next": "A ledger only works when every joule ends up in a named destination.",
    },
    "gravitational_store_factor_confusion": {
        "title": "Gravitational store comparison",
        "diagnosis": "The answer is collapsing mass, field strength, and height into one vague rule.",
        "repair": "Hold two factors steady and change one at a time so the store comparison stays honest.",
        "notice_next": "The store comparison is clearer when the changing factor is named explicitly.",
    },
    "useful_transfer_confusion": {
        "title": "Useful gain vs total transfer",
        "diagnosis": "The answer is treating the useful gain as identical to the full input transfer.",
        "repair": "Keep the total hand-off and the useful part separate, then place the losses where they occur.",
        "notice_next": "Useful output becomes smaller whenever leaks are real parts of the chain.",
    },
    "power_efficiency_confusion": {
        "title": "Power vs efficiency",
        "diagnosis": "The answer is turning 'faster' into 'more efficient' without checking the useful fraction.",
        "repair": "Use time for power and useful fraction for efficiency, then keep those two comparisons apart.",
        "notice_next": "Rate and yield are different questions even when they describe the same machine.",
    },
    "multi_stage_energy_order": {
        "title": "Multi-stage energy order",
        "diagnosis": "The answer is skipping straight to the final stage without following the intermediate gains and losses.",
        "repair": "Run the chain in sequence so each stage becomes the next stage's input before you judge the outcome.",
        "notice_next": "Multi-stage problems usually break when one intermediate step is skipped.",
    },
}


def _title_case_tag(tag: str) -> str:
    title = str(tag or "").replace("concept_", "").replace("_", " ").strip()
    return " ".join(part[:1].upper() + part[1:] for part in title.split())


def _template_from_heuristic(tag: str) -> Dict[str, str]:
    if "graph" in tag:
        return {
            "title": "Graph meaning interpretation",
            "diagnosis": "The answer is reading the graph by surface appearance instead of by the quantity shown on each axis.",
            "repair": "Name the axes, then decide what the feature means physically before you choose an answer.",
            "notice_next": "Graph questions usually reward physics meaning over visual pattern-matching.",
        }
    if "vector" in tag or "direction" in tag:
        return {
            "title": "Direction-sensitive quantity reasoning",
            "diagnosis": "The answer is losing the directional part of the quantity and flattening it into a size-only idea.",
            "repair": "Ask whether direction changes the meaning of the quantity before you classify or compare it.",
            "notice_next": "Shared units do not guarantee two quantities mean the same thing.",
        }
    if "force" in tag or "torque" in tag or "stability" in tag:
        return {
            "title": "Force-system reasoning",
            "diagnosis": "The answer is not keeping the object, pivot, or resultant clear enough before predicting the outcome.",
            "repair": "Reduce the situation to one object or pivot, then decide what the combined force or turning effect says.",
            "notice_next": "Mechanics gets clearer when the force story is tied to one system at a time.",
        }
    if "energy" in tag or "power" in tag or "efficiency" in tag or "work" in tag:
        return {
            "title": "Energy-transfer accounting",
            "diagnosis": "The answer is not keeping the full transfer chain and the useful share separate enough.",
            "repair": "Track input, useful gain, and leak in order before deciding what reaches the final store.",
            "notice_next": "Energy questions reward honest accounting more than shortcut language.",
        }
    if "unit" in tag or "measurement" in tag or "prefix" in tag:
        return {
            "title": "Measurement and unit reasoning",
            "diagnosis": "The answer is using a number rule without anchoring it to the physical scale or unit meaning.",
            "repair": "State the quantity and conversion factor first, then complete the number step.",
            "notice_next": "A safe measurement answer can always explain the scale behind it.",
        }
    return {
        "title": _title_case_tag(tag),
        "diagnosis": "The answer is mixing up the core relationship this question is testing.",
        "repair": "Name the quantity or relationship first, then rebuild the answer from that idea instead of from pattern-matching.",
        "notice_next": "When the idea is named clearly, the exam move usually becomes much easier to see.",
    }


def misconception_summary_for_tag(tag: Optional[str]) -> Optional[MisconceptionSummary]:
    normalized = str(tag or "").strip()
    if not normalized:
        return None
    template = EXACT_SUMMARIES.get(normalized) or _template_from_heuristic(normalized)
    return {
        "tag": normalized,
        "title": template["title"],
        "diagnosis": template["diagnosis"],
        "repair": template["repair"],
        "notice_next": template["notice_next"],
    }


def misconception_summaries_for_tags(tags: List[str], limit: int = 3) -> List[MisconceptionSummary]:
    seen = set()
    summaries: List[MisconceptionSummary] = []
    for tag in tags:
        summary = misconception_summary_for_tag(tag)
        if not summary:
            continue
        normalized = summary["tag"]
        if normalized in seen:
            continue
        seen.add(normalized)
        summaries.append(summary)
        if len(summaries) >= limit:
            break
    return summaries
