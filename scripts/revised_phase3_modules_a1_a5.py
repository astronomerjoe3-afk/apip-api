from __future__ import annotations

import argparse
from copy import deepcopy
from typing import Any, Dict, List, Sequence, Tuple

try:
    from scripts.revised_core_curriculum_modules import _build_generated_bundle, acceptance_groups, auto_blueprint, mcq, short, tw
except ModuleNotFoundError:
    from revised_core_curriculum_modules import _build_generated_bundle, acceptance_groups, auto_blueprint, mcq, short, tw


TermTuple = Tuple[str, str, str]
ControlTuple = Tuple[str, str, str]
ReadoutTuple = Tuple[str, str]


def _terms(items: Sequence[TermTuple]) -> List[Dict[str, str]]:
    return [tw(term, meaning, why) for term, meaning, why in items]


def _bp(
    *,
    slug: str,
    title: str,
    focus: str,
    terms: Sequence[TermTuple],
    core: Sequence[str],
    equation: str,
    meaning: str,
    units: Sequence[str],
    conditions: str,
    reason: str,
    contrast: str,
    correct_statement: str,
    sim_concept: str,
    controls: Sequence[ControlTuple],
    readouts: Sequence[ReadoutTuple],
    mapping: Sequence[str],
    trap: str,
    relation_prompt_focus: str = "",
) -> Dict[str, Any]:
    lead_term = terms[0][0]
    compare_term = terms[1][0] if len(terms) > 1 else title
    blueprint = auto_blueprint(
        slug=slug,
        title=title,
        focus=focus,
        terms=_terms(terms),
        core_concepts=list(core),
        equation=equation,
        meaning=meaning,
        units=list(units),
        conditions=conditions,
        summary=f"{title} becomes clearer when {focus}.",
        why_prompt=f"Why is it useful to explain {title.lower()} by keeping {focus} visible?",
        why_answer=reason,
        compare_prompt=f"How is {lead_term.lower()} different from {compare_term.lower()} in {title.lower()}?",
        compare_answer=contrast,
        apply_prompt=f"Which statement best matches {title.lower()}?",
        apply_choices=[
            correct_statement,
            f"{title} can be answered from labels alone without checking the underlying relationship.",
            f"{title} works best when the main mechanism is ignored and only one keyword is memorized.",
            f"{title} is not helped by comparing quantities, paths, or thresholds carefully.",
        ],
        apply_answer_index=0,
        sim_concept=sim_concept,
        sim_focus_prompt=f"Use the lesson explorer to keep {focus} visible.",
        sim_description=f"Compare the main quantities and relationships in {title.lower()} on one board.",
        sim_baseline=f"Start with the default {title.lower()} setup and read the first comparison carefully.",
        sim_tasks=[
            f"Change one control and compare how {lead_term.lower()} behaves.",
            f"Change a second control and decide whether {focus} still stays readable.",
        ],
        sim_takeaway=f"{title} is easier to trust when {focus}.",
        sim_controls=list(controls),
        sim_readouts=list(readouts),
        reflection_prompt=f"Explain {title.lower()} in one strong paragraph without reducing it to a memorized slogan.",
        trap=trap,
        analogy_check=f"Which part of the analogy keeps {focus} visible?",
        analogy_mapping=list(mapping),
        visual_concept=sim_concept,
    )
    if relation_prompt_focus.strip():
        blueprint["relation_prompt_focus"] = relation_prompt_focus.strip()
    return blueprint


def _module(
    *,
    module_id: str,
    title: str,
    content_version: str,
    sequence: int,
    model_name: str,
    description: str,
    mastery_outcomes: Sequence[str],
    lessons: Sequence[Dict[str, Any]],
) -> Tuple[Dict[str, Any], List[Tuple[str, Dict[str, Any]]], List[Tuple[str, Dict[str, Any]]]]:
    return _build_generated_bundle(
        module_id=module_id,
        module_title=title,
        content_version=content_version,
        sequence=sequence,
        level=f"Module {module_id}",
        estimated_minutes=90,
        model_name=model_name,
        module_description=description,
        mastery_outcomes=mastery_outcomes,
        lessons=lessons,
    )


def _definition_choices(terms: Sequence[Dict[str, str]], index: int) -> Tuple[str, List[str]]:
    entries = list(terms)
    target = entries[index % len(entries)]
    distractors = [entry["meaning"] for entry in entries if entry["term"] != target["term"]][:3]
    while len(distractors) < 3:
        distractors.append("It is a different lesson idea, not the one being defined here.")
    return target["term"], [target["meaning"], *distractors[:3]]


def _generic_statement_choices(correct: str) -> List[str]:
    return [
        correct,
        "The lesson can be answered from labels alone without checking the mechanism.",
        "The lesson works best when the main relationship is ignored.",
        "The lesson should be reduced to a memorized slogan instead of a physical explanation.",
    ]


def _generic_relation_choices(correct: str) -> List[str]:
    return [
        correct,
        "The lesson has no reusable relation because only the labels matter.",
        "The relation can be reversed universally without checking conditions.",
        "Only one quantity matters, so the rest of the relation can be ignored.",
    ]


def _relation_prompt(prompt: str, focus: str) -> str:
    cleaned_focus = str(focus).strip()
    if not cleaned_focus:
        return prompt
    stem = prompt[:-1] if prompt.endswith("?") else prompt
    return f"{stem} when {cleaned_focus}?"


def _phase3_extra_question_banks(module_id: str, lesson_index: int, blueprint: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    slug = str(blueprint["slug"])
    lesson_id = f"{module_id}L{lesson_index}"
    skills = [
        f"{slug}_summary",
        f"{slug}_mechanism",
        f"{slug}_definition",
        f"{slug}_relation",
        f"{slug}_application",
    ]
    terms = list(blueprint["terms"])
    title = str(blueprint["title"])
    core_concepts = [str(item) for item in blueprint["core_concepts"]]
    summary = str(blueprint["summary"])
    equation = str(blueprint["formula"]["equation"])
    why_answers = list(blueprint["why_answers"])
    compare_answers = list(blueprint["compare_answers"])
    why_groups = list(blueprint["why_groups"])
    compare_groups = list(blueprint["compare_groups"])
    relation_prompt_focus = str(blueprint.get("relation_prompt_focus") or "")
    term_a, choices_a = _definition_choices(terms, 2)
    term_b, choices_b = _definition_choices(terms, 3)

    return {
        "diagnostic": [
            mcq(
                f"{lesson_id}_D7",
                f"Which core idea should stay visible in {title.lower()}?",
                _generic_statement_choices(core_concepts[0]),
                0,
                "Keep the main lesson mechanism visible before narrowing to a label.",
                skill_tags=[skills[0]],
            ),
            mcq(
                f"{lesson_id}_D8",
                f"Which definition best matches {term_a} in {title.lower()}?",
                choices_a,
                0,
                f"Keep {term_a} tied to the lesson's actual role.",
                skill_tags=[skills[2]],
            ),
            short(
                f"{lesson_id}_D9",
                f"What mechanism should stay visible when you explain {title.lower()}?",
                why_answers,
                "Use the lesson's cause-and-effect language rather than a memorized slogan.",
                skill_tags=[skills[1]],
                acceptance_rules=acceptance_groups(*why_groups),
            ),
            mcq(
                f"{lesson_id}_D10",
                _relation_prompt(
                    f"Which relation clue best belongs to {title.lower()}?",
                    relation_prompt_focus,
                ),
                _generic_relation_choices(equation),
                0,
                "Use the lesson relation as a compact summary of the physics.",
                skill_tags=[skills[3]],
            ),
        ],
        "concept": [
            mcq(
                f"{lesson_id}_C5",
                f"Which summary best protects the main idea in {title.lower()}?",
                _generic_statement_choices(summary),
                0,
                "Pick the option that keeps the lesson mechanism visible.",
                skill_tags=[skills[0]],
            ),
            short(
                f"{lesson_id}_C6",
                f"Which contrast must you keep clear in {title.lower()}?",
                compare_answers,
                "State the contrast explicitly instead of collapsing the two ideas together.",
                skill_tags=[skills[1]],
                acceptance_rules=acceptance_groups(*compare_groups),
            ),
            mcq(
                f"{lesson_id}_C7",
                f"Which definition best matches {term_b} here?",
                choices_b,
                0,
                f"Keep {term_b} attached to this lesson's meaning.",
                skill_tags=[skills[2]],
            ),
            mcq(
                f"{lesson_id}_C8",
                _relation_prompt(
                    f"Which relation or rule should guide a fresh {title.lower()} check?",
                    relation_prompt_focus,
                ),
                _generic_relation_choices(equation),
                0,
                "Use the lesson relation as a guide in the new case.",
                skill_tags=[skills[3]],
            ),
        ],
        "mastery": [
            mcq(
                f"{lesson_id}_M7",
                f"Which transfer statement best fits {title.lower()} in a new case?",
                list(blueprint["apply_choices"]),
                int(blueprint["apply_answer_index"]),
                "Keep the lesson mechanism visible in the new scenario.",
                skill_tags=[skills[4]],
            ),
            short(
                f"{lesson_id}_M8",
                f"What lesson mechanism must remain visible in this new {title.lower()} case?",
                why_answers,
                "Use the same mechanism language you would trust in a worked explanation.",
                skill_tags=[skills[1]],
                acceptance_rules=acceptance_groups(*why_groups),
            ),
            mcq(
                f"{lesson_id}_M9",
                f"Which definition still matters most when you transfer {title.lower()}?",
                choices_a,
                0,
                "A transfer question still depends on the core lesson definitions.",
                skill_tags=[skills[2]],
            ),
            mcq(
                f"{lesson_id}_M10",
                f"Which summary best avoids the main trap in {title.lower()}?",
                _generic_statement_choices(core_concepts[min(1, len(core_concepts) - 1)]),
                0,
                "Pick the option that keeps the weak shortcut out of the explanation.",
                skill_tags=[skills[0]],
            ),
        ],
    }


def _upgrade_phase3_lessons(module_id: str, lesson_pairs: List[Tuple[str, Dict[str, Any]]], blueprints: Sequence[Dict[str, Any]]) -> None:
    for lesson_index, ((_, lesson), blueprint) in enumerate(zip(lesson_pairs, blueprints), start=1):
        contract = lesson["authoring_contract"]
        diagnostic = lesson["phases"]["diagnostic"]["items"]
        concept = lesson["phases"]["concept_reconstruction"]["capsules"][0]["checks"]
        mastery = lesson["phases"]["transfer"]["items"]
        extras = _phase3_extra_question_banks(module_id, lesson_index, blueprint)

        diagnostic.extend(deepcopy(extras["diagnostic"]))
        concept.extend(deepcopy(extras["concept"]))
        mastery.extend(deepcopy(extras["mastery"]))

        contract["assessment_bank_targets"] = {
            "diagnostic_pool_min": 10,
            "concept_gate_pool_min": 8,
            "mastery_pool_min": 10,
            "fresh_attempt_policy": "Prefer unseen lesson-owned questions in diagnostic, concept-gate, and mastery before repeating any previous stem.",
        }

        clarity_checks = [str(item) for item in contract.get("visual_clarity_checks") or []]
        extra_clip_check = "No picture labels, angle marks, or callouts clip on desktop or mobile layouts."
        if extra_clip_check not in clarity_checks:
            clarity_checks.append(extra_clip_check)
        contract["visual_clarity_checks"] = clarity_checks


A1_CONTENT_VERSION = "20260323_a1_particle_port_exchange_v2"
A1_MODULE_TITLE = "Matter, Radiation and Particles"
A1_MODULE_DESCRIPTION = "Matter is built from a small cast of travelers and bundles, and every interaction is a swap checked by strict conservation gates."
A1_MASTERY_OUTCOMES = [
    "Describe subatomic structure using photons, quarks, leptons, baryons, mesons, and antiparticles correctly.",
    "Classify hadrons into baryons and mesons using their quark content.",
    "Describe interactions with exchange particles instead of treating forces as detached pushes.",
    "Apply charge, baryon-number, and lepton-number conservation to particle events.",
]

_A1_BLUEPRINTS = [
    _bp(slug="subatomic_inventory", title="Subatomic Inventory", focus="matter travelers, radiation messengers, and nucleus bundles stay distinct", terms=[("Photon", "A photon is the quantum messenger of electromagnetic radiation.", "It keeps radiation inside the particle story."), ("Lepton", "A lepton is a solo traveler such as an electron or neutrino.", "It blocks the false idea that every particle is a hadron."), ("Nucleon", "A nucleon is a proton or neutron in the nucleus.", "It separates nuclear bundles from electrons outside the nucleus."), ("Subatomic particle", "A subatomic particle is a component or messenger smaller than an atom.", "It gives the module a clean inventory view.")], core=["Atoms contain electrons around nuclei made from protons and neutrons.", "Photons carry radiation and energy inside the same event world as matter particles.", "Leptons are not hadrons, while nucleons are composite hadrons.", "Classification should come before interaction stories."], equation="particle inventory and charge tags", meaning="The first safe step is to identify what class of particle or messenger is present.", units=["e", "MeV"], conditions="Use as an entry point before quark structure and interaction rules.", reason="Because photons, leptons, and nucleons play different roles in atomic and particle events, so mixing them hides the structure of the topic.", contrast="A photon is a radiation messenger, while a lepton is a matter traveler.", correct_statement="A strong particle inventory keeps radiation messengers, solo travelers, and nucleus bundles separate from the start.", sim_concept="particle_inventory", controls=[("particle_type", "Traveler type", "It changes which family the selected particle belongs to."), ("charge_tag", "Charge tag", "It helps compare neutral and charged travelers."), ("zone_view", "Atomic zone", "It shows whether the item belongs in the nucleus, outside it, or in transit as radiation.")], readouts=[("family_label", "Shows whether the item is radiation, matter, or a composite nuclear particle."), ("charge_readout", "Shows the particle charge for comparison."), ("role_hint", "Shows the particle role in atomic structure or events.")], mapping=["Messenger token = photon", "Solo traveler = lepton", "Nucleus bundle = nucleon", "Port inventory = particle classification"], trap="Do not collapse photons, leptons, and nucleons into one generic small-particle category."),
    _bp(slug="quarks_hadrons", title="Quarks, Baryons and Mesons", focus="quark packing decides whether a hadron is a three-pack crate or a pair parcel", terms=[("Quark", "A quark is a fundamental particle that combines to form hadrons.", "It explains hadron structure."), ("Baryon", "A baryon is a hadron made from three quarks.", "It gives protons and neutrons a structural rule."), ("Meson", "A meson is a hadron made from a quark-antiquark pair.", "It separates pair parcels from three-pack crates."), ("Hadron", "A hadron is a quark-built particle held by the strong interaction.", "It is the umbrella family for baryons and mesons.")], core=["Hadrons are composite particles built from quarks.", "Baryons contain three quarks.", "Mesons contain a quark-antiquark pair.", "Protons and neutrons are baryons, not elementary particles."], equation="baryon = q q q; meson = q anti-q", meaning="Quark packing decides the hadron family.", units=["charge in e"], conditions="Use for classifying hadrons and reading simple quark structures.", reason="Because the quark packing rule is what distinguishes baryons from mesons, not size or charge alone.", contrast="A baryon is a three-quark hadron, while a meson is a quark-antiquark hadron.", correct_statement="The safest way to classify hadrons is to check whether the quark packing is three quarks or a quark-antiquark pair.", sim_concept="hadron_builder", controls=[("quark_mix", "Quark mix", "It changes the composition of the selected hadron."), ("antiquark_toggle", "Mirror partner switch", "It introduces an antiquark when testing meson structure."), ("family_sort", "Packing rule filter", "It groups the finished bundle as baryon or meson.")], readouts=[("hadron_family", "Shows whether the built particle is a baryon or meson."), ("quark_count", "Shows how many quarks or antiquarks are present."), ("composition_summary", "Shows the structural rule used to classify the hadron.")], mapping=["Cargo pieces = quarks", "Three-pack crate = baryon", "Pair parcel = meson", "Family stamp = hadron classification"], trap="Do not sort hadrons by size or charge first and forget the quark-composition rule."),
    _bp(slug="antiparticles_pairs", title="Antiparticles, Pair Production and Annihilation", focus="mirror partners and photons trade places only when the event still balances", terms=[("Antiparticle", "An antiparticle has the same mass as its partner but opposite charge and matching opposite quantum numbers where relevant.", "It makes pair processes readable."), ("Annihilation", "Annihilation is the process where a particle and its antiparticle disappear into photons or other allowed products.", "It shows matter-radiation exchange in one event."), ("Pair production", "Pair production is the creation of a particle-antiparticle pair from a photon or photons with enough energy.", "It is the reverse-style event of annihilation."), ("Rest energy", "Rest energy is the energy associated with mass even when the particle is not moving.", "It explains why a photon needs enough energy to make a pair.")], core=["Antiparticles are matched partners, not unrelated extra particles.", "Annihilation converts a particle pair into radiation while obeying conservation rules.", "Pair production needs enough photon energy to create both members of the pair.", "Matter-radiation exchange still has to pass the ledger gates."], equation="photon energy can create or replace rest energy when the full event balances", meaning="Energy and quantum numbers must still balance when particles become photons or vice versa.", units=["MeV", "e"], conditions="Use for qualitative annihilation and pair-production reasoning.", reason="Because pair production must supply the rest energy of both new particles while still satisfying the conservation ledger.", contrast="Annihilation turns a particle-antiparticle pair into photons, while pair production uses photon energy to create the pair.", correct_statement="Pair production and annihilation are opposite-style matter-radiation exchanges, but both still have to obey conservation rules.", sim_concept="antimatter_pairing", controls=[("pair_type", "Mirror pair", "It selects which particle-antiparticle pair is being tested."), ("photon_energy", "Messenger energy", "It changes whether pair production can pass the threshold."), ("event_mode", "Swap mode", "It toggles between annihilation and pair-production views.")], readouts=[("ledger_status", "Shows whether charge and energy checks are satisfied."), ("product_list", "Shows which particles or photons appear after the event."), ("energy_margin", "Shows whether the photon budget is above or below threshold.")], mapping=["Mirror partner = antiparticle", "Messenger token = photon", "Swap event = annihilation or pair production", "Ledger gate = conservation check"], trap="Do not treat pair production as magic creation without an energy and conservation check."),
    _bp(slug="interactions_exchange", title="Interactions and Exchange Particles", focus="messenger tokens carry the interaction instead of an unexplained push", terms=[("Fundamental interaction", "A fundamental interaction is a basic way particles influence one another.", "It organizes particle events into families."), ("Exchange particle", "An exchange particle is the messenger that carries an interaction between particles.", "It turns forces into swap events."), ("Strong interaction", "The strong interaction binds quarks inside hadrons and helps bind nucleons in nuclei.", "It explains hadron and nucleus stability."), ("Weak interaction", "The weak interaction is involved in processes such as beta decay and neutrino interactions.", "It connects particle change to nuclear and lepton events.")], core=["Interactions can be modeled as messenger-token exchanges.", "Different interactions have different roles and ranges.", "The strong interaction is a binding story.", "The weak interaction is associated with particle-changing processes."], equation="interaction type is identified by the messenger and the allowed change", meaning="To classify an event, ask what changes and which messenger is involved.", units=["charge", "energy", "momentum"], conditions="Use for qualitative interaction classification while still checking conserved charge, energy, and momentum rather than numerical cross sections.", reason="Because the exchange-particle picture shows how the interaction is carried between particles and helps classify the event cleanly.", contrast="The strong interaction is a binding story, while the weak interaction is a particle-change story.", correct_statement="An interaction is easier to classify when you ask which messenger is involved and what change the event allows.", sim_concept="interaction_exchange", controls=[("interaction_family", "Force family", "It changes which fundamental interaction is highlighted."), ("messenger_type", "Messenger token", "It shows the exchange particle attached to the event picture."), ("event_change", "Allowed change", "It changes whether the event is binding, scattering, or identity-changing.")], readouts=[("family_match", "Shows the best interaction classification."), ("messenger_role", "Shows what the exchange particle is doing in the event."), ("change_signature", "Shows the particle change or binding outcome being tested.")], mapping=["Messenger token = exchange particle", "Swap rule = interaction", "Binding route = strong interaction", "Change route = weak interaction"], trap="Do not collapse all interactions into one generic force story with no messenger or event signature.", relation_prompt_focus="charge, energy, and momentum clues must still agree with the messenger story"),
    _bp(slug="conservation_rules", title="Conservation Rules", focus="every particle event must pass the charge, baryon-number, and lepton-number gates", terms=[("Charge conservation", "Charge conservation says total electric charge is the same before and after an event.", "It is the first ledger gate in many particle questions."), ("Baryon number", "Baryon number tracks baryons as plus one and antibaryons as minus one.", "It stops impossible matter-balance stories."), ("Lepton number", "Lepton number tracks leptons and antileptons through particle events.", "It is essential for beta and neutrino events."), ("Particle event ledger", "A particle event ledger is the before-and-after audit of conserved quantities.", "It turns event analysis into a balance problem.")], core=["Charge is conserved in every allowed particle event.", "Baryon number and lepton number are useful bookkeeping tags.", "A strange-looking final state can still be allowed if the gates balance.", "Conservation checks are the fastest first filter for event questions."], equation="total charge, baryon number, and lepton number must balance across the event", meaning="Before-and-after bookkeeping decides whether the event is allowed.", units=["charge and number tags"], conditions="Use when checking particle decays, collisions, and reactions qualitatively.", reason="Because conserved quantities quickly show whether a proposed event is allowed before you spend time on finer details.", contrast="Charge conservation tracks electric charge, while baryon and lepton number track the relevant matter families through the event.", correct_statement="A proposed particle event must satisfy the conservation ledger before you trust any story about how it happened.", sim_concept="conservation_gate", controls=[("event_choice", "Event card", "It selects which reaction or decay is being audited."), ("outgoing_edit", "Cargo edit", "It changes one product so the ledger can be rechecked."), ("gate_view", "Ledger gate", "It isolates charge, baryon number, or lepton number for inspection.")], readouts=[("charge_balance", "Shows whether total charge balances."), ("baryon_balance", "Shows whether baryon number balances."), ("lepton_balance", "Shows whether lepton number balances.")], mapping=["Port ledger = conservation table", "Charge gate = charge conservation", "Baryon gate = baryon-number conservation", "Lepton gate = lepton-number conservation"], trap="Do not trust a reaction just because the particle names sound plausible; audit the conserved quantities first."),
    _bp(slug="particle_event_analysis", title="Particle Event Analysis", focus="classification, interaction clues, and ledger checks need to be read together", terms=[("Reaction channel", "A reaction channel is one allowed set of products from a particle interaction.", "It organizes alternative outcomes."), ("Decay", "A decay is the spontaneous transformation of an unstable particle into other particles.", "It is a common event family that still obeys conservation rules."), ("Scattering", "Scattering is an interaction where incoming particles deflect or exchange energy and momentum.", "It broadens event analysis beyond simple decay."), ("Event interpretation", "Event interpretation is the process of deciding what particle story best fits the observed products.", "It combines classification, interactions, and conservation.")], core=["A full event analysis combines particle identity, interaction type, and conservation rules.", "Different reaction channels can be compared by the products they allow.", "Decay and scattering are different event families, but both still obey the same bookkeeping checks.", "Good event interpretation is a structured process, not one lucky guess."], equation="event analysis = classify particles + identify interaction + audit conservation", meaning="A reliable interpretation uses several checks, not one clue only.", units=["charge", "baryon number", "lepton number", "energy", "momentum"], conditions="Use when interpreting qualitative particle-event diagrams or reaction statements while auditing conserved charge, baryon number, lepton number, energy, and momentum.", reason="Because a strong event interpretation also needs the interaction type and the conservation checks, not just one striking product clue.", contrast="A decay is a spontaneous transformation of one unstable particle, while scattering is an interaction in which incoming particles deflect or exchange energy and momentum.", correct_statement="The safest event interpretation combines classification, interaction clues, and conservation checks before deciding on the channel.", sim_concept="event_classifier", controls=[("event_card", "Event card", "It changes which full particle event is being interpreted."), ("clue_layer", "Clue layer", "It highlights family, messenger, or conservation evidence."), ("channel_toggle", "Reaction channel", "It compares alternative allowed product sets.")], readouts=[("best_fit", "Shows the strongest event interpretation."), ("interaction_hint", "Shows which interaction family best fits the event."), ("ledger_summary", "Shows whether the full event passes the conservation checks.")], mapping=["Full port board = particle event", "Route option = reaction channel", "Unload event = decay", "Deflection swap = scattering"], trap="Do not decide the event type from a single striking particle and ignore the rest of the board.", relation_prompt_focus="charge, baryon number, lepton number, energy, and momentum checks are read together"),
]

A1_MODULE_DOC, A1_LESSONS, A1_SIM_LABS = _module(
    module_id="A1",
    title=A1_MODULE_TITLE,
    content_version=A1_CONTENT_VERSION,
    sequence=18,
    model_name="Particle-Port Exchange Model",
    description=A1_MODULE_DESCRIPTION,
    mastery_outcomes=A1_MASTERY_OUTCOMES,
    lessons=_A1_BLUEPRINTS,
)
_upgrade_phase3_lessons("A1", A1_LESSONS, _A1_BLUEPRINTS)


A2_CONTENT_VERSION = "20260323_a2_ladder_gate_packet_v2"
A2_MODULE_TITLE = "Quantum Phenomena and Atomic Spectra"
A2_MODULE_DESCRIPTION = "Atoms hold electrons on locked energy floors, packets of exactly the right size can lift or free them, and the return jumps paint spectral barcodes."
A2_MASTERY_OUTCOMES = [
    "Explain quantized energy levels, excitation, and ionisation using photon packets and threshold ideas.",
    "Explain emission and absorption spectra as evidence for discrete atomic energy levels.",
    "Apply the photoelectric-effect model using threshold frequency, work function, and photon energy.",
    "Describe de Broglie wavelength and wave-particle duality as linked quantum ideas rather than isolated slogans.",
]

_A2_BLUEPRINTS = [
    _bp(slug="quantized_energy_levels", title="Quantized Energy Levels", focus="electrons occupy locked energy floors so only exact packet sizes move them", terms=[("Energy level", "An energy level is a discrete allowed energy state for an electron in an atom.", "It is the foundation of atomic spectra."), ("Quantized", "Quantized means limited to specific allowed values rather than any continuous value.", "It protects the ladder-floor idea."), ("Excitation", "Excitation is the lifting of an electron to a higher energy level.", "It makes later emission and absorption readable."), ("Ground state", "The ground state is the lowest allowed energy level of the atom.", "It is the natural reference point for electron jumps.")], core=["Atomic electrons occupy discrete energy levels.", "An electron changes level only by taking or giving the right energy packet.", "Excitation lifts an electron away from the ground state.", "The ladder picture makes later spectra and ionisation ideas coherent."], equation="Delta E = h f", meaning="A photon packet must match the energy gap for an allowed transition.", units=["J", "Hz", "eV"], conditions="Use when relating photon energy to transitions between discrete atomic levels.", reason="Because the atomic energy levels are quantized, so the electron can only move if it receives a packet that matches an allowed gap.", contrast="The ground state is the lowest allowed level, while an excited state is a higher allowed level reached after absorbing the right packet.", correct_statement="An atomic ladder works only because the allowed energy floors are discrete and photon packets must match the gaps.", sim_concept="energy_ladder", controls=[("photon_packet", "Packet size", "It changes the incoming photon energy."), ("level_layout", "Ladder spacing", "It changes the allowed energy gaps."), ("start_level", "Starting floor", "It changes which jump is being attempted.")], readouts=[("transition_result", "Shows whether the electron jumps, stays put, or returns later."), ("gap_match", "Shows whether the packet matches the required energy difference."), ("state_label", "Shows the current electron level.")], mapping=["Locked floor = energy level", "Lift packet = photon", "Ground floor = ground state", "Raised floor = excited state"], trap="Do not treat atomic energy as a continuous ramp where any packet can partly lift the electron."),
    _bp(slug="spectral_barcodes", title="Emission and Absorption Spectra", focus="return jumps and missing-color gates produce line spectra because only certain energy differences are allowed", terms=[("Emission spectrum", "An emission spectrum is the set of discrete wavelengths emitted when electrons fall to lower levels.", "It turns return jumps into visible evidence."), ("Absorption spectrum", "An absorption spectrum is the set of wavelengths removed when electrons absorb specific photon energies.", "It shows the same energy gaps from the opposite direction."), ("Line spectrum", "A line spectrum contains discrete lines rather than a continuous spread.", "It is the fingerprint of quantized levels."), ("Transition", "A transition is a jump from one energy level to another.", "It connects the ladder model to the spectrum lines.")], core=["Emission lines come from downward transitions that release photon packets.", "Absorption lines come from upward transitions that remove specific photon packets.", "Line spectra are evidence for discrete energy levels.", "Each atom has its own spectral barcode because its level spacings are different."], equation="line energy = atomic level difference", meaning="Each spectral line corresponds to one allowed transition between levels.", units=["nm", "eV", "Hz"], conditions="Use when connecting spectral lines to discrete energy-level differences.", reason="Because the electron can only change between discrete energy levels, so only specific photon energies and wavelengths are emitted or absorbed.", contrast="An absorption spectrum shows wavelengths removed by upward transitions, while an emission spectrum shows wavelengths produced by downward transitions.", correct_statement="Line spectra are the visible barcode of allowed atomic transitions, not random color fragments.", sim_concept="spectral_barcode", controls=[("transition_choice", "Jump choice", "It changes which level transition is being viewed."), ("spectrum_mode", "Barcode mode", "It toggles between emission and absorption views."), ("atom_type", "Atom ladder", "It changes the level spacing pattern for comparison.")], readouts=[("line_positions", "Shows where the spectral lines appear."), ("transition_labels", "Shows which level jumps produced the lines."), ("barcode_compare", "Shows how two atoms differ in spectral pattern.")], mapping=["Return jump = emission transition", "Missing-color gate = absorption line", "Barcode line = spectral line", "Ladder spacing = energy gap pattern"], trap="Do not treat spectrum lines as decorative colors unrelated to specific level transitions.", relation_prompt_focus="energy, wavelength, and frequency comparisons must stay tied to the allowed transition"),
    _bp(slug="photoelectric_effect", title="Photoelectric Effect", focus="surface electrons leave only when each incoming packet is energetic enough", terms=[("Photoelectric effect", "The photoelectric effect is the emission of electrons from a surface when light above threshold frequency strikes it.", "It is key evidence for photon packets."), ("Threshold frequency", "Threshold frequency is the minimum light frequency needed to release electrons from a surface.", "It blocks the intensity-only misconception."), ("Work function", "The work function is the minimum energy needed to liberate an electron from the surface.", "It is the unlock gate for the material."), ("Photoelectron", "A photoelectron is an electron emitted from the surface by the photoelectric effect.", "It is the outgoing traveler in the event.")], core=["Photoelectron emission depends on photon energy, so frequency matters directly.", "Below threshold frequency, no electrons are emitted however bright the light becomes.", "Above threshold, intensity mainly changes the emission rate.", "The photoelectric effect is strong evidence for quantized light packets."], equation="h f = phi + K_max", meaning="Photon energy pays the unlock cost and any remaining energy becomes maximum photoelectron kinetic energy.", units=["J", "Hz", "eV"], conditions="Use for photon-energy reasoning at a photoelectric surface.", reason="Because each photon below threshold is still too weak to overcome the work function, so no individual electron gets enough energy to leave.", contrast="Threshold frequency decides whether each photon can release an electron, while intensity mainly changes how many photons arrive each second.", correct_statement="In the photoelectric effect, frequency controls whether emission is possible and intensity mainly affects how many electrons are emitted once threshold is passed.", sim_concept="photoelectric_threshold", controls=[("frequency", "Packet beat", "It changes the photon energy."), ("intensity", "Packet flow rate", "It changes how many photons strike the surface each second."), ("work_function", "Unlock gate", "It changes the surface threshold.")], readouts=[("emission_status", "Shows whether photoelectrons are emitted."), ("electron_rate", "Shows how many electrons are emitted."), ("kmax", "Shows the maximum photoelectron kinetic energy.")], mapping=["Unlock gate = work function", "Lift packet = photon", "Released traveler = photoelectron", "Threshold beat = threshold frequency"], trap="Do not explain photoelectric emission with brightness alone and ignore the threshold packet size."),
    _bp(slug="excitation_ionisation", title="Excitation and Ionisation", focus="some packets only lift an electron while larger packets free it completely from the atom", terms=[("Ionisation", "Ionisation is the complete removal of an electron from the atom.", "It is the full unlock case beyond ordinary excitation."), ("Ionisation energy", "Ionisation energy is the minimum energy needed to remove an electron completely from the atom.", "It sets the top exit gate of the ladder."), ("Excited state", "An excited state is a higher allowed atomic level reached without removing the electron from the atom.", "It is a lifted but still bound state."), ("Continuum", "The continuum is the range of energies above the ionisation threshold where the electron is no longer bound.", "It separates bound levels from free states.")], core=["Excitation keeps the electron bound in the atom, while ionisation frees it completely.", "Ionisation needs more energy than a smaller bound-state transition.", "A packet can be above an excitation gap yet still below ionisation.", "The atomic ladder ends at a threshold above which the electron is free."], equation="packet energy can excite or ionise depending on which threshold it reaches", meaning="Different packet sizes produce different outcomes on the same atomic ladder.", units=["eV", "J"], conditions="Use for comparing bound-state transitions with full electron removal.", reason="Because a photon can match an internal level gap without being large enough to reach the full ionisation threshold.", contrast="Excitation moves the electron to a higher bound level, while ionisation removes the electron from the atom completely.", correct_statement="Ionisation is not just a larger excitation; it is the threshold where the electron leaves the atom altogether.", sim_concept="excitation_ionisation", controls=[("packet_energy", "Packet size", "It changes whether the atom is only excited or fully ionised."), ("threshold_view", "Gate view", "It highlights bound-state gaps and the top exit threshold."), ("atom_ladder", "Atom type", "It changes the ladder spacing and ionisation threshold.")], readouts=[("outcome_label", "Shows whether the atom stayed in the ground state, became excited, or was ionised."), ("bound_state", "Shows whether the electron is still bound to the atom."), ("energy_margin", "Shows how far the packet is below or above the next threshold.")], mapping=["Lifted floor = excited state", "Top exit gate = ionisation threshold", "Freed traveler = ionised electron", "Bound ladder = discrete atomic levels"], trap="Do not treat every absorbed packet as if it must ionise the atom.", relation_prompt_focus="energy, threshold, and eV-level comparisons must stay linked to the packet outcome"),
    _bp(slug="de_broglie_duality", title="de Broglie Wavelength and Wave-Particle Duality", focus="matter travelers can carry a track ripple, so localized hits and wave-like patterns belong to one description", terms=[("Wave-particle duality", "Wave-particle duality means quantum objects show both localized particle-like and wave-like behavior depending on the experiment.", "It prevents the false either-or view."), ("de Broglie wavelength", "The de Broglie wavelength is the wavelength associated with a particle's momentum.", "It connects matter motion to wave behavior."), ("Diffraction", "Diffraction is the spreading of waves after passing through an aperture or around an obstacle.", "It provides evidence for wave behavior."), ("Momentum", "Momentum is the quantity p = m v for the moving particle.", "It sets the matter-wave wavelength scale.")], core=["Quantum objects can be detected as particles while still producing wave-like patterns.", "The de Broglie relation links momentum to wavelength.", "Shorter wavelength corresponds to larger momentum.", "Wave-particle duality is about experiment-dependent evidence, not a classical contradiction."], equation="lambda = h / p", meaning="A particle with larger momentum has a shorter associated wavelength.", units=["m", "kg m s^-1"], conditions="Use when relating matter-wave behavior to particle momentum.", reason="Because quantum experiments show localized detections together with diffraction or interference patterns, so both aspects belong to one description.", contrast="Increasing momentum makes the de Broglie wavelength smaller because wavelength is inversely related to momentum.", correct_statement="Wave-particle duality is strongest when particles are treated as producing localized detections while also carrying a wavelength that affects patterns.", sim_concept="de_broglie_track", controls=[("momentum", "Traveler momentum", "It changes the associated de Broglie wavelength."), ("aperture_width", "Gap width", "It changes how strongly the wave behavior shows up."), ("display_mode", "Evidence view", "It toggles between localized hits and pattern buildup.")], readouts=[("wavelength", "Shows the de Broglie wavelength."), ("pattern_width", "Shows the strength of diffraction or spread."), ("detection_map", "Shows the localized arrival positions.")], mapping=["Track ripple = de Broglie wavelength", "Traveler hit = particle detection", "Spread pattern = wave behavior", "Momentum dial = p"], trap="Do not turn wave-particle duality into a simple either-or label that erases half the evidence."),
    _bp(slug="quantum_evidence", title="Atomic Spectra and Quantum Evidence", focus="spectra, photoelectric thresholds, and matter-wave behavior point back to one packet-and-level quantum structure", terms=[("Spectral evidence", "Spectral evidence is observational support taken from discrete emission or absorption lines.", "It keeps spectra tied to atomic structure."), ("Quantum model", "A quantum model uses discrete states and packet exchanges to explain atomic behavior.", "It unifies several advanced ideas in one framework."), ("Threshold behavior", "Threshold behavior is the sudden onset of an effect only after a critical value is exceeded.", "It appears in photoelectric and ionisation ideas."), ("Atomic spectrum", "An atomic spectrum is the set of allowed spectral lines associated with one atom.", "It is the fingerprint output of its energy ladder.")], core=["Several experiments point to the same quantum picture rather than to unrelated tricks.", "Spectra support discrete atomic levels.", "Photoelectric thresholds support packet-like photon energy transfer.", "Matter-wave behavior supports quantum descriptions beyond classical particle motion."], equation="quantum evidence is consistent when packet, threshold, and level ideas agree", meaning="Different experiments support one coherent quantum model.", units=["spectral lines and thresholds"], conditions="Use for synthesis across the full quantum module.", reason="Because spectra, thresholds, and matter-wave patterns all support one coherent quantum model built on discrete levels and packet exchanges.", contrast="Threshold behavior in the photoelectric effect and line spectra both point to quantized energies, but they show that idea through different experiments.", correct_statement="Quantum theory gains strength because several different experiments point to the same packet-and-level structure.", sim_concept="wave_particle_evidence", controls=[("evidence_panel", "Evidence panel", "It toggles between spectra, photoelectric, and matter-wave views."), ("quantum_filter", "Model lens", "It highlights the quantum principle being supported."), ("comparison_mode", "Cross-check mode", "It places two evidence types side by side.")], readouts=[("support_map", "Shows which quantum idea is supported by the chosen evidence."), ("shared_principle", "Shows the common packet-or-level theme across experiments."), ("evidence_summary", "Shows the strongest synthesis statement for the comparison.")], mapping=["Evidence board = experiment set", "Shared ladder = quantized model", "Threshold gate = packet condition", "Pattern clue = wave behavior"], trap="Do not leave the module as a list of disconnected facts when several experiments point to one quantum framework."),
]

A2_MODULE_DOC, A2_LESSONS, A2_SIM_LABS = _module(
    module_id="A2",
    title=A2_MODULE_TITLE,
    content_version=A2_CONTENT_VERSION,
    sequence=19,
    model_name="Ladder-Gate Packet Model of Quantum Atoms",
    description=A2_MODULE_DESCRIPTION,
    mastery_outcomes=A2_MASTERY_OUTCOMES,
    lessons=_A2_BLUEPRINTS,
)
_upgrade_phase3_lessons("A2", A2_LESSONS, _A2_BLUEPRINTS)


A3_CONTENT_VERSION = "20260323_a3_phase_loom_v2"
A3_MODULE_TITLE = "Advanced Waves and Optics"
A3_MODULE_DESCRIPTION = "Wave paths can add, cancel, lock into standing patterns, and reveal structure through phase, diffraction, refraction, and guided-light routes."
A3_MASTERY_OUTCOMES = [
    "Explain progressive and stationary waves using superposition, phase, and boundary ideas.",
    "Apply path difference and phase difference qualitatively to interference and diffraction patterns.",
    "Use diffraction-grating and simple refraction ideas to interpret advanced wave and optics setups.",
    "Explain critical angle, total internal reflection, and oscilloscope traces as coherent wave evidence.",
]

_A3_BLUEPRINTS = [
    _bp(
        slug="progressive_superposition",
        title="Progressive Waves and Superposition",
        focus="wave contributions add at the same place and time instead of taking turns",
        terms=[
            ("Progressive wave", "A progressive wave transfers energy as the disturbance travels through space.", "It separates traveling patterns from stationary ones."),
            ("Superposition", "Superposition says the total displacement is the sum of the overlapping displacements.", "It is the core addition rule for waves."),
            ("Displacement", "Displacement is the signed distance of the medium from equilibrium.", "It is the quantity that adds during overlap."),
            ("Phase", "Phase tells where a point is in its oscillation cycle.", "It helps compare whether two contributions reinforce or cancel."),
        ],
        core=[
            "Progressive waves travel while carrying energy.",
            "When waves overlap, displacements add by superposition.",
            "Reinforcement and cancellation depend on phase.",
            "Superposition is a rule about adding displacement, not about waves vanishing permanently.",
        ],
        equation="total displacement = displacement 1 + displacement 2",
        meaning="At one point and one instant, overlapping disturbances add algebraically.",
        units=["m", "s", "phase comparison"],
        conditions="Use for overlapping waves in the same medium where the linear superposition rule is valid.",
        reason="Because each wave contributes its own displacement at the same point, so the combined disturbance is the sum of those contributions.",
        contrast="A progressive wave travels through the medium, while superposition is the rule used when two or more waves overlap.",
        correct_statement="The safest way to read overlapping waves is to add their displacements at the same place and time.",
        sim_concept="progressive_superposition",
        controls=[
            ("phase_offset", "Phase offset", "It changes whether the overlap is reinforcing or cancelling."),
            ("amplitude_pair", "Wave amplitudes", "It changes how strongly each wave contributes."),
            ("snapshot_mode", "Instant view", "It freezes one moment so the displacement sum can be checked."),
        ],
        readouts=[
            ("combined_trace", "Shows the summed displacement pattern."),
            ("phase_compare", "Shows whether the selected points are aligned or opposed."),
            ("displacement_sum", "Shows the algebraic result at the chosen location."),
        ],
        mapping=[
            "Thread strip = wave trace",
            "Overlay rule = superposition",
            "Rise or dip token = displacement",
            "Cycle offset = phase difference",
        ],
        trap="Do not treat overlap as one wave taking turns with the other instead of adding at the same instant.",
        relation_prompt_focus="phase, path, and trace comparisons stay aligned at one point and one time",
    ),
    _bp(
        slug="stationary_waves",
        title="Stationary Waves",
        focus="standing patterns come from two matched waves traveling in opposite directions",
        terms=[
            ("Stationary wave", "A stationary wave is a standing pattern formed by two opposite-traveling waves of the same frequency.", "It explains fixed nodes and antinodes."),
            ("Node", "A node is a point that remains at zero displacement in a stationary wave.", "It is the fixed quiet point in the pattern."),
            ("Antinode", "An antinode is a point of maximum oscillation amplitude in a stationary wave.", "It marks where the oscillation is strongest."),
            ("Harmonic", "A harmonic is one allowed standing-wave mode in the system.", "It connects boundary conditions to allowed patterns."),
        ],
        core=[
            "Stationary waves are formed by superposition of matched opposite-traveling waves.",
            "Nodes stay fixed at zero displacement.",
            "Antinodes are the points of greatest amplitude.",
            "Only certain harmonics fit the boundary conditions.",
        ],
        equation="for a string fixed at both ends, n lambda = 2L",
        meaning="Only wavelengths that fit the boundary condition produce standing modes.",
        units=["m", "Hz", "mode number"],
        conditions="Use for idealized fixed-boundary systems such as strings or air columns with simple mode patterns.",
        reason="Because the standing pattern appears only when the returning wave matches the outgoing wave so that fixed quiet points and strong oscillation points stay locked in place.",
        contrast="A node never oscillates, while an antinode oscillates with the greatest amplitude in that mode.",
        correct_statement="A stationary wave is a standing mode made by two matched opposite-traveling waves, not a single wave that stopped moving.",
        sim_concept="stationary_wave_modes",
        controls=[
            ("mode_number", "Harmonic", "It changes which standing pattern is being tested."),
            ("boundary_length", "System length", "It changes which wavelengths can fit."),
            ("drive_frequency", "Drive frequency", "It changes whether the chosen mode is supported cleanly."),
        ],
        readouts=[
            ("node_count", "Shows how many nodes appear in the chosen mode."),
            ("antinodes", "Shows where the strongest oscillation points are."),
            ("fit_status", "Shows whether the wavelength matches the boundary condition."),
        ],
        mapping=[
            "Locked pattern = stationary wave",
            "Quiet peg = node",
            "Wide swing point = antinode",
            "Mode card = harmonic",
        ],
        trap="Do not describe a stationary wave as a progressive wave that somehow froze in place.",
        relation_prompt_focus="wavelength and frequency checks must fit the standing-wave pattern",
    ),
    _bp(
        slug="phase_path_interference",
        title="Phase Difference, Path Difference and Interference",
        focus="route-length difference controls whether meeting waves reinforce or cancel",
        terms=[
            ("Interference", "Interference is the pattern produced when coherent waves superpose.", "It turns phase comparison into visible outcomes."),
            ("Path difference", "Path difference is the difference in route length traveled by two waves.", "It is the route measure that sets the meeting condition."),
            ("Phase difference", "Phase difference compares how far apart two oscillations are in the cycle.", "It translates route difference into wave alignment."),
            ("Coherent sources", "Coherent sources maintain a constant phase relationship.", "They are needed for stable interference patterns."),
        ],
        core=[
            "Stable interference requires coherent sources.",
            "Path difference determines phase relationship.",
            "Whole-wavelength path differences reinforce.",
            "Half-odd-wavelength path differences cancel.",
        ],
        equation="constructive: path difference = n lambda; destructive: path difference = (n + 1/2) lambda",
        meaning="The route difference decides whether meeting waves are in phase or out of phase.",
        units=["m", "wavelengths", "radians or degrees"],
        conditions="Use for two-source interference or path-comparison reasoning with coherent waves.",
        reason="Because the difference in traveled distance changes how the wave cycles line up when they meet, which decides whether the amplitudes add or cancel.",
        contrast="Path difference is the distance mismatch between routes, while phase difference is the cycle mismatch that results from it.",
        correct_statement="Interference is strongest when path difference is used to predict the meeting phase before adding amplitudes.",
        sim_concept="interference_path_phase",
        controls=[
            ("path_gap", "Route difference", "It changes the path difference between the two waves."),
            ("wavelength", "Wavelength", "It changes how strongly the same route gap shifts phase."),
            ("coherence_lock", "Coherence lock", "It toggles between stable and unstable phase relation."),
        ],
        readouts=[
            ("phase_gap", "Shows the resulting phase difference."),
            ("fringe_type", "Shows whether the selected point is reinforcing or cancelling."),
            ("route_ratio", "Shows path difference as a fraction or multiple of wavelength."),
        ],
        mapping=[
            "Twin route = two-source path",
            "Route mismatch = path difference",
            "Cycle mismatch = phase difference",
            "Bright meet / dark meet = constructive or destructive interference",
        ],
        trap="Do not jump straight to bright-or-dark language without checking path difference first.",
    ),
    _bp(
        slug="diffraction_gratings",
        title="Diffraction and Diffraction Gratings",
        focus="tight gaps and repeated slits spread waves into ordered angle patterns",
        terms=[
            ("Diffraction", "Diffraction is the spreading of a wave after passing through a gap or past an edge.", "It explains why waves bend into shadow regions."),
            ("Diffraction grating", "A diffraction grating is a large set of equally spaced slits.", "It creates sharp interference maxima."),
            ("Grating spacing", "Grating spacing is the distance between adjacent slits in the grating.", "It controls the diffraction angles."),
            ("Order", "Order labels a bright maximum in the grating pattern.", "It turns the angle pattern into a countable family."),
        ],
        core=[
            "Diffraction becomes more pronounced when the gap is comparable to wavelength.",
            "A diffraction grating creates narrow bright orders through repeated interference.",
            "Smaller grating spacing gives larger diffraction angles for the same wavelength.",
            "Longer wavelength spreads to larger angles in the same grating.",
        ],
        equation="d sin theta = n lambda",
        meaning="The grating spacing, order number, and wavelength set the bright-angle condition.",
        units=["m", "degrees", "order number"],
        conditions="Use for diffraction-grating angle reasoning with monochromatic or separated wavelengths.",
        reason="Because each slit acts as a coherent source, and only certain output angles keep the wave contributions lined up across the whole grating.",
        contrast="Ordinary diffraction is the spreading from one gap or edge, while a diffraction grating uses many repeated gaps to create sharp ordered maxima.",
        correct_statement="A diffraction grating is best read as repeated-slit interference that selects particular bright angles.",
        sim_concept="diffraction_grating_orders",
        controls=[
            ("grating_spacing", "Slit spacing", "It changes the angle needed to keep neighboring slits in step."),
            ("wavelength", "Wavelength", "It changes how much the pattern spreads."),
            ("order_select", "Order", "It picks which maximum is being tracked."),
        ],
        readouts=[
            ("angle_readout", "Shows the predicted angle for the selected order."),
            ("pattern_width", "Shows how broad the spread is."),
            ("order_status", "Shows whether the chosen order is allowed for the current values."),
        ],
        mapping=[
            "Gap fan = diffraction spread",
            "Repeated comb = diffraction grating",
            "Comb spacing = grating spacing",
            "Bright lane = diffraction order",
        ],
        trap="Do not describe a grating as just one wider slit with the same physics as a single opening.",
    ),
    _bp(
        slug="refraction_tir",
        title="Refraction, Critical Angle and Total Internal Reflection",
        focus="speed change at a boundary redirects the route, and beyond the critical angle the wave stays trapped",
        terms=[
            ("Refraction", "Refraction is the change in direction caused by a change in wave speed between media.", "It ties bending to speed, not sideways force."),
            ("Refractive index", "Refractive index measures how much the wave speed is reduced in a medium.", "It helps compare optical density and route bending."),
            ("Critical angle", "The critical angle is the incident angle in the denser medium that gives a refracted angle of 90 degrees.", "It marks the threshold for total internal reflection."),
            ("Total internal reflection", "Total internal reflection occurs when no refracted ray emerges and the wave is reflected back into the denser medium.", "It explains light guiding in optical systems."),
        ],
        core=[
            "Refraction comes from a change in wave speed across the boundary.",
            "The refracted direction depends on the speed ratio between the media.",
            "A critical angle exists only when trying to go from denser to less dense medium.",
            "Above that angle, total internal reflection traps the ray in the denser medium.",
        ],
        equation="n1 sin theta1 = n2 sin theta2",
        meaning="The refractive-index pair sets how the route angles relate across the boundary.",
        units=["degrees", "refractive index"],
        conditions="Use for simple optical boundary questions, including critical-angle and fiber-guiding reasoning.",
        reason="Because the wave front changes speed at the boundary, so the route bends; once the needed refracted angle would exceed 90 degrees, the wave remains internally reflected instead.",
        contrast="Refraction is boundary bending due to speed change, while total internal reflection is the no-exit case above the critical angle in the denser medium.",
        correct_statement="The safest way to explain boundary bending is to track the speed change and ask whether the critical-angle threshold has been crossed.",
        sim_concept="critical_angle_routes",
        controls=[
            ("medium_pair", "Medium pair", "It changes the refractive-index contrast."),
            ("incident_angle", "Incident angle", "It tests whether the route refracts or becomes fully internal."),
            ("boundary_mode", "Boundary mode", "It switches between ordinary refraction and guided-light view."),
        ],
        readouts=[
            ("refracted_angle", "Shows the transmitted route angle when refraction occurs."),
            ("critical_angle", "Shows the threshold angle for the selected media."),
            ("route_result", "Shows whether the wave refracts or undergoes total internal reflection."),
        ],
        mapping=[
            "Boundary gate = interface",
            "Speed shift = refractive-index change",
            "Threshold tilt = critical angle",
            "Trapped route = total internal reflection",
        ],
        trap="Do not treat refraction as if the boundary adds a sideways force instead of changing wave speed.",
    ),
    _bp(
        slug="oscilloscope_wave_evidence",
        title="Oscilloscope Traces and Wave Evidence",
        focus="a time trace turns invisible oscillations into readable frequency, amplitude, and phase comparisons",
        terms=[
            ("Oscilloscope", "An oscilloscope displays voltage against time as a trace.", "It makes fast wave behavior readable."),
            ("Time base", "The time base sets how much time each horizontal division represents.", "It is needed to extract frequency or period."),
            ("Amplitude", "Amplitude is the maximum displacement or voltage from equilibrium.", "It sets the vertical size of the trace."),
            ("Period", "The period is the time for one full cycle.", "It links the trace to frequency."),
        ],
        core=[
            "An oscilloscope shows a changing signal as a time trace.",
            "Horizontal scale gives time information and vertical scale gives amplitude information.",
            "Period and frequency can be extracted from the trace.",
            "Comparing traces side by side reveals phase difference.",
        ],
        equation="f = 1 / T",
        meaning="Frequency is the reciprocal of the measured period.",
        units=["s", "Hz", "V"],
        conditions="Use for sinusoidal trace interpretation and qualitative phase comparison on oscilloscopes.",
        reason="Because the oscilloscope turns a changing signal into a scaled time graph, so period, amplitude, and phase can be read directly from the trace spacing and height.",
        contrast="The time base sets the horizontal time scale, while amplitude is read from the vertical size of the trace.",
        correct_statement="An oscilloscope trace is strongest when it is read as a scaled graph of voltage against time, not as a picture to memorize.",
        sim_concept="oscilloscope_traces",
        controls=[
            ("time_base", "Time base", "It changes how much time each division represents."),
            ("signal_frequency", "Signal frequency", "It changes how many cycles fit on the screen."),
            ("phase_shift", "Phase shift", "It changes how two traces line up."),
        ],
        readouts=[
            ("period_measure", "Shows the measured time for one cycle."),
            ("frequency_measure", "Shows the derived frequency."),
            ("phase_compare", "Shows how far apart the traces are in the cycle."),
        ],
        mapping=[
            "Screen trace = oscilloscope output",
            "Horizontal divisions = time base",
            "Trace height = amplitude",
            "Cycle spacing = period and frequency evidence",
        ],
        trap="Do not read an oscilloscope trace as a route-in-space diagram when it is a graph against time.",
    ),
]

A3_MODULE_DOC, A3_LESSONS, A3_SIM_LABS = _module(
    module_id="A3",
    title=A3_MODULE_TITLE,
    content_version=A3_CONTENT_VERSION,
    sequence=20,
    model_name="Phase-Loom Model of Advanced Waves",
    description=A3_MODULE_DESCRIPTION,
    mastery_outcomes=A3_MASTERY_OUTCOMES,
    lessons=_A3_BLUEPRINTS,
)
_upgrade_phase3_lessons("A3", A3_LESSONS, _A3_BLUEPRINTS)


A4_CONTENT_VERSION = "20260323_a4_vector_rig_v2"
A4_MODULE_TITLE = "Advanced Mechanics and Materials"
A4_MODULE_DESCRIPTION = "Motion, balance, impacts, turning paths, springs, and stretched materials all become clearer when vectors, constraints, and stored response are read on one rig."
A4_MASTERY_OUTCOMES = [
    "Resolve forces and motion into components and use equilibrium conditions in one and two dimensions.",
    "Apply one-dimensional and projectile-motion reasoning using consistent vector and kinematic relationships.",
    "Use momentum and energy ideas to interpret collisions and circular motion.",
    "Explain springs, stress, strain, and Young modulus as linked response ideas in materials.",
]

_A4_BLUEPRINTS = [
    _bp(
        slug="vector_equilibrium",
        title="Vector Resolution and Equilibrium",
        focus="forces balance only after their components are compared on shared axes",
        terms=[
            ("Vector", "A vector has magnitude and direction.", "It is the natural language for forces and motion."),
            ("Component", "A component is the projection of a vector on a chosen axis.", "It makes diagonal forces calculable."),
            ("Equilibrium", "Equilibrium means the resultant force and resultant moment are balanced for the situation studied.", "It is the balance condition for the rig."),
            ("Resultant", "The resultant is the single vector equivalent to the combined effect of several vectors.", "It shows whether the system is balanced or not."),
        ],
        core=[
            "Vectors must be resolved before diagonal balances are judged cleanly.",
            "Equilibrium requires the resultant effect on the chosen axes to be zero.",
            "Component comparison is safer than visual guesswork with angled arrows.",
            "Balance is a vector condition, not a simple count of arrows.",
        ],
        equation="for translational equilibrium, Sigma Fx = 0 and Sigma Fy = 0",
        meaning="The net component on each chosen axis must cancel.",
        units=["N", "degrees"],
        conditions="Use for static or steady-motion cases where translational equilibrium is being tested.",
        reason="Because a diagonal force can still produce an unbalanced horizontal or vertical effect, so the safest balance check is to compare components axis by axis.",
        contrast="A vector is the full directed quantity, while a component is only the part of that vector along one chosen axis.",
        correct_statement="Balance questions are most trustworthy after the forces are resolved into components and summed on the chosen axes.",
        sim_concept="vector_rig_balance",
        controls=[
            ("force_angle", "Force angle", "It changes how the vector splits between horizontal and vertical axes."),
            ("force_size", "Force size", "It changes the magnitude that must be balanced."),
            ("axis_view", "Axis view", "It toggles the component breakdown on the rig."),
        ],
        readouts=[
            ("horizontal_sum", "Shows the resultant horizontal component."),
            ("vertical_sum", "Shows the resultant vertical component."),
            ("balance_status", "Shows whether equilibrium is satisfied."),
        ],
        mapping=[
            "Rig arrow = vector",
            "Axis shadow = component",
            "Balance board = equilibrium check",
            "Combined pull = resultant",
        ],
        trap="Do not decide equilibrium from the picture alone when the arrows point at angles.",
        relation_prompt_focus="acceleration must stay zero while the resolved components balance on each axis",
    ),
    _bp(
        slug="kinematics_maps",
        title="One-Dimensional and Two-Dimensional Motion",
        focus="position, velocity, and acceleration need separate component stories instead of one blended motion label",
        terms=[
            ("Velocity", "Velocity is the rate of change of displacement and has direction.", "It distinguishes directed motion from speed alone."),
            ("Acceleration", "Acceleration is the rate of change of velocity.", "It tells how the motion state is changing."),
            ("Displacement", "Displacement is the directed change in position.", "It anchors kinematics to a vector quantity."),
            ("Component motion", "Component motion treats horizontal and vertical motion separately before recombining them.", "It is vital in two-dimensional reasoning."),
        ],
        core=[
            "Velocity, displacement, and acceleration are distinct quantities.",
            "Two-dimensional motion is usually safest when split into independent components.",
            "A zero component acceleration in one direction does not erase acceleration in another direction.",
            "Kinematic descriptions improve when position, velocity, and acceleration are kept separate.",
        ],
        equation="v = u + a t",
        meaning="Velocity changes from its initial value according to acceleration over time.",
        units=["m", "m s^-1", "m s^-2", "s"],
        conditions="Use for constant-acceleration reasoning in one direction or in separated components.",
        reason="Because motion in two dimensions can only be read clearly if the horizontal and vertical changes are tracked separately instead of blended into one vague path description.",
        contrast="Velocity tells the motion state at an instant, while acceleration tells how that velocity is changing.",
        correct_statement="Two-dimensional motion becomes easier when each component keeps its own displacement, velocity, and acceleration story.",
        sim_concept="kinematics_component_map",
        controls=[
            ("initial_velocity", "Initial velocity", "It changes the starting motion state."),
            ("acceleration_vector", "Acceleration vector", "It changes how the motion state evolves."),
            ("component_view", "Component board", "It toggles one-dimensional versus two-dimensional breakdown."),
        ],
        readouts=[
            ("velocity_components", "Shows the current horizontal and vertical velocity values."),
            ("position_components", "Shows the separate position changes on each axis."),
            ("acceleration_components", "Shows which directions are changing."),
        ],
        mapping=[
            "Motion rig = moving object",
            "Axis lane = component direction",
            "State card = velocity",
            "Change card = acceleration",
        ],
        trap="Do not merge position, velocity, and acceleration into one everyday description of motion.",
    ),
    _bp(
        slug="projectile_motion",
        title="Projectile Motion",
        focus="launch motion splits into horizontal and vertical stories that share the same clock but not the same acceleration",
        terms=[
            ("Projectile", "A projectile is an object moving under gravity after launch, with no further driving force assumed.", "It frames the path after release."),
            ("Horizontal component", "The horizontal component is the sideways part of the launch velocity.", "It sets the sideways motion."),
            ("Vertical component", "The vertical component is the up-down part of the launch velocity.", "It sets the rise and fall behavior."),
            ("Time of flight", "Time of flight is the total time the projectile remains in the air for the chosen model.", "It links the two component stories with one clock."),
        ],
        core=[
            "Projectile motion is analyzed by splitting the launch velocity into components.",
            "Horizontal and vertical motion share time but have different acceleration stories.",
            "Gravity gives the vertical acceleration throughout the flight.",
            "The parabolic path emerges from combining the two component motions.",
        ],
        equation="horizontal: x = ux t; vertical: y = uy t - 1/2 g t^2",
        meaning="The horizontal part follows uniform motion while the vertical part follows constant downward acceleration.",
        units=["m", "s", "m s^-1", "m s^-2"],
        conditions="Use for ideal projectile motion with air resistance neglected.",
        reason="Because the sideways and vertical motions evolve differently, and the clearest analysis keeps them separate while using the same elapsed time for both.",
        contrast="The horizontal component has no acceleration in the ideal model, while the vertical component changes under gravity.",
        correct_statement="Projectile motion is most reliable when the launch is split into horizontal and vertical components before the path is recombined.",
        sim_concept="projectile_split",
        controls=[
            ("launch_speed", "Launch speed", "It changes both components together before they are split."),
            ("launch_angle", "Launch angle", "It changes how much of the speed goes into each component."),
            ("gravity", "Gravity", "It changes the vertical acceleration story."),
        ],
        readouts=[
            ("component_breakdown", "Shows the horizontal and vertical launch components."),
            ("flight_time", "Shows the time the projectile remains in the air."),
            ("range_height", "Shows the resulting horizontal range and maximum height."),
        ],
        mapping=[
            "Launch rig = projectile setup",
            "Side lane = horizontal component",
            "Drop lane = vertical component",
            "Shared clock = common flight time",
        ],
        trap="Do not carry the downward gravitational acceleration into the horizontal component in the ideal projectile model.",
    ),
    _bp(
        slug="momentum_collisions",
        title="Momentum, Impulse and Collisions",
        focus="impact questions work best when momentum change is audited before energy-story shortcuts are used",
        terms=[
            ("Momentum", "Momentum is the product of mass and velocity.", "It is the central bookkeeping quantity in collisions."),
            ("Impulse", "Impulse is the change in momentum produced by a force acting over a time interval.", "It links force and collision time to momentum change."),
            ("Elastic collision", "An elastic collision conserves kinetic energy as well as momentum in the ideal model.", "It contrasts with inelastic outcomes."),
            ("Inelastic collision", "An inelastic collision conserves momentum but not kinetic energy.", "It keeps momentum conservation separate from energy distribution."),
        ],
        core=[
            "Momentum bookkeeping is the first safe check in collision questions.",
            "Impulse measures the momentum change delivered during a force-time interaction.",
            "Kinetic energy behavior distinguishes elastic from inelastic collisions.",
            "Collision analysis is more reliable when before-and-after states are compared systematically.",
        ],
        equation="impulse = Delta p",
        meaning="The force-time action changes the object's momentum by the same amount.",
        units=["kg m s^-1", "N s"],
        conditions="Use for collisions, rebounds, and force-time change questions.",
        reason="Because momentum is the quantity that is conserved for the whole system in collisions, so it gives the safest first ledger before you judge how the kinetic energy changed.",
        contrast="An elastic collision conserves both momentum and kinetic energy, while an inelastic collision conserves momentum but redistributes kinetic energy.",
        correct_statement="Collision questions are strongest when momentum is checked first and energy is then used to classify the outcome.",
        sim_concept="collision_ledger",
        controls=[
            ("mass_pair", "Object masses", "It changes the momentum carried by each object."),
            ("velocity_pair", "Incoming velocities", "It changes the before-collision momentum ledger."),
            ("collision_mode", "Collision type", "It switches between elastic and inelastic outcomes."),
        ],
        readouts=[
            ("momentum_before_after", "Shows the total momentum before and after the collision."),
            ("impulse_value", "Shows the momentum change for the selected object."),
            ("energy_compare", "Shows how kinetic energy changed through the impact."),
        ],
        mapping=[
            "Impact ledger = momentum bookkeeping",
            "Push burst = impulse",
            "Springy hit = elastic collision",
            "Stickier hit = inelastic collision",
        ],
        trap="Do not assume kinetic energy is always conserved just because momentum is conserved.",
    ),
    _bp(
        slug="circular_motion",
        title="Circular Motion",
        focus="turning motion needs an inward acceleration and inward resultant force even when the speed stays constant",
        terms=[
            ("Centripetal acceleration", "Centripetal acceleration is the inward acceleration required for circular motion.", "It explains why the velocity direction keeps changing."),
            ("Centripetal force", "Centripetal force is the inward resultant force producing the circular path.", "It is not a separate outward force."),
            ("Tangential velocity", "Tangential velocity is the instantaneous velocity along the tangent to the circular path.", "It keeps speed and direction distinct."),
            ("Radius", "Radius is the distance from the center of the circle to the moving object.", "It sets the curvature scale of the path."),
        ],
        core=[
            "An object in circular motion has changing velocity because the direction changes continuously.",
            "That directional change requires inward centripetal acceleration.",
            "The required resultant force also points inward.",
            "There is no extra outward driving force in the inertial-frame explanation.",
        ],
        equation="a = v^2 / r and F = m v^2 / r",
        meaning="For a given speed, tighter curvature requires greater inward acceleration and force.",
        units=["m", "m s^-1", "m s^-2", "N"],
        conditions="Use for uniform circular motion in an inertial-frame treatment.",
        reason="Because the velocity direction changes at every moment on the circle, so there must be an inward acceleration and resultant force to keep turning the path.",
        contrast="Tangential velocity points along the path, while centripetal acceleration points toward the center.",
        correct_statement="Uniform circular motion still needs acceleration because the direction of velocity changes even when the speed does not.",
        sim_concept="circular_turning",
        controls=[
            ("speed", "Speed", "It changes how strongly the object needs to turn."),
            ("radius", "Radius", "It changes the curvature of the path."),
            ("mass", "Mass", "It changes the required inward force while leaving the acceleration relation visible."),
        ],
        readouts=[
            ("centripetal_acceleration", "Shows the inward acceleration required for the turn."),
            ("centripetal_force", "Shows the inward resultant force."),
            ("velocity_direction", "Shows the tangent direction at the selected point."),
        ],
        mapping=[
            "Turn ring = circular path",
            "Inward pull = centripetal force",
            "Turn need = centripetal acceleration",
            "Sideways arrow = tangential velocity",
        ],
        trap="Do not invent a separate outward force to explain why the object keeps turning.",
    ),
    _bp(
        slug="springs_materials",
        title="Springs, Stress, Strain and Young Modulus",
        focus="materials respond to load by storing stretch or changing length in a way that must be compared to their size and area",
        terms=[
            ("Spring constant", "The spring constant measures how stiff a spring is in Hooke's-law behavior.", "It links force to extension."),
            ("Stress", "Stress is force per unit cross-sectional area.", "It compares load with the size of the material."),
            ("Strain", "Strain is extension divided by original length.", "It compares change in length with the starting size."),
            ("Young modulus", "Young modulus is the ratio of stress to strain in the elastic region.", "It measures material stiffness rather than spring stiffness."),
        ],
        core=[
            "Hooke's-law spring response links force to extension in the proportional region.",
            "Stress and strain normalize material response for size and area.",
            "Young modulus compares how hard a material is to stretch elastically.",
            "Material behavior must be read relative to geometry, not by force alone.",
        ],
        equation="F = k x; stress = F / A; strain = Delta L / L; E = stress / strain",
        meaning="Springs and materials respond to load through proportional measures of extension and normalized deformation.",
        units=["N", "m", "Pa"],
        conditions="Use in the elastic region for Hooke's-law and Young-modulus style reasoning.",
        reason="Because the same force can produce very different effects depending on area, original length, and stiffness, so materials must be compared with normalized quantities instead of raw load only.",
        contrast="Stress compares force with area, while strain compares extension with original length.",
        correct_statement="A material question is strongest when load, geometry, and proportional response are read together instead of by force alone.",
        sim_concept="materials_response",
        controls=[
            ("load_force", "Load force", "It changes the applied pull on the spring or sample."),
            ("cross_section", "Area", "It changes the stress for the same force."),
            ("original_length", "Original length", "It changes how the same extension compares as strain."),
        ],
        readouts=[
            ("extension", "Shows the resulting change in length."),
            ("stress_strain", "Shows the normalized stress and strain values."),
            ("stiffness_compare", "Shows how the spring or material response changes."),
        ],
        mapping=[
            "Load rig = applied force",
            "Stretch mark = extension",
            "Area gate = stress comparison",
            "Response ratio = Young modulus",
        ],
        trap="Do not compare material response with force alone and ignore cross-sectional area or original length.",
    ),
]

A4_MODULE_DOC, A4_LESSONS, A4_SIM_LABS = _module(
    module_id="A4",
    title=A4_MODULE_TITLE,
    content_version=A4_CONTENT_VERSION,
    sequence=21,
    model_name="Vector-Rig Model of Mechanics and Materials",
    description=A4_MODULE_DESCRIPTION,
    mastery_outcomes=A4_MASTERY_OUTCOMES,
    lessons=_A4_BLUEPRINTS,
)
_upgrade_phase3_lessons("A4", A4_LESSONS, _A4_BLUEPRINTS)


A5_CONTENT_VERSION = "20260323_a5_swing_return_v2"
A5_MODULE_TITLE = "Oscillations"
A5_MODULE_DESCRIPTION = "A good oscillator returns toward balance, swaps energy between stretch and speed, and responds very differently when the driving rhythm matches or misses its natural return pattern."
A5_MASTERY_OUTCOMES = [
    "Explain oscillations and simple harmonic motion using restoring tendency, displacement, velocity, and acceleration together.",
    "Interpret SHM graphs and equations as linked views of one oscillating system.",
    "Explain energy changes in SHM without losing the restoring-force story.",
    "Describe resonance, damping, and forced oscillations as response ideas rather than isolated buzzwords.",
]

_A5_BLUEPRINTS = [
    _bp(
        slug="oscillation_basics",
        title="Oscillations and Restoring Tendency",
        focus="an oscillator repeatedly returns toward equilibrium because the restoring effect points back toward the center",
        terms=[
            ("Oscillation", "An oscillation is a repeated motion about an equilibrium position.", "It defines the whole module world."),
            ("Equilibrium position", "The equilibrium position is the balance point about which the motion occurs.", "It anchors the return story."),
            ("Restoring force", "A restoring force acts toward the equilibrium position.", "It is the reason the motion keeps returning."),
            ("Amplitude", "Amplitude is the maximum displacement from equilibrium.", "It measures the size of the oscillation."),
        ],
        core=[
            "Oscillations are repeated motions about equilibrium.",
            "A restoring effect points back toward the balance position.",
            "Amplitude is the maximum displacement from equilibrium.",
            "An oscillator is most readable when displacement and restoring tendency are tracked together.",
        ],
        equation="restoring effect points toward equilibrium",
        meaning="The return tendency is directed back toward the center position.",
        units=["m", "s", "qualitative force direction"],
        conditions="Use as the first model for systems that repeatedly move around a stable equilibrium.",
        reason="Because the motion can only keep repeating if some restoring effect always acts back toward the equilibrium position after displacement.",
        contrast="Equilibrium is the balance point itself, while amplitude is how far the oscillator moves away from it.",
        correct_statement="An oscillation is best explained as repeated motion about equilibrium driven by a restoring tendency back toward the center.",
        sim_concept="oscillation_return",
        controls=[
            ("displacement", "Starting displacement", "It changes how far the oscillator begins from equilibrium."),
            ("restoring_strength", "Return strength", "It changes how strongly the system is pulled back."),
            ("friction_level", "Resistance", "It changes how cleanly the oscillation continues."),
        ],
        readouts=[
            ("equilibrium_marker", "Shows the balance position."),
            ("amplitude_readout", "Shows the maximum displacement reached."),
            ("return_direction", "Shows whether the restoring effect points back toward equilibrium."),
        ],
        mapping=[
            "Center peg = equilibrium",
            "Return pull = restoring force",
            "Wide swing = amplitude",
            "Repeat run = oscillation",
        ],
        trap="Do not describe oscillation as any repeated motion if there is no restoring tendency toward equilibrium.",
        relation_prompt_focus="displacement, amplitude, and period clues stay tied to the restoring motion",
    ),
    _bp(
        slug="simple_harmonic_motion",
        title="Simple Harmonic Motion",
        focus="the return acceleration is proportional to displacement and always directed back toward equilibrium",
        terms=[
            ("Simple harmonic motion", "Simple harmonic motion is oscillation where acceleration is proportional to displacement and directed toward equilibrium.", "It gives the formal condition for SHM."),
            ("Displacement", "Displacement is the signed distance from equilibrium.", "It sets the restoring response."),
            ("Acceleration", "Acceleration is the rate of change of velocity.", "In SHM it points toward equilibrium."),
            ("Angular frequency", "Angular frequency sets how quickly the SHM cycles repeat.", "It connects the motion to the equations."),
        ],
        core=[
            "SHM is defined by acceleration being proportional to displacement and opposite in direction.",
            "Maximum displacement coincides with maximum restoring acceleration magnitude.",
            "Acceleration is zero at equilibrium in the ideal model.",
            "The SHM condition is stronger than simply saying the motion repeats.",
        ],
        equation="a = - omega^2 x",
        meaning="Acceleration is proportional to displacement and directed oppositely.",
        units=["m", "m s^-2", "rad s^-1"],
        conditions="Use for ideal SHM models such as small spring oscillations or other linear restoring systems.",
        reason="Because SHM requires a very specific return rule: the farther the oscillator is displaced, the larger the acceleration back toward equilibrium becomes.",
        contrast="An oscillation only repeats, while SHM obeys the specific proportional restoring condition a = -omega^2 x.",
        correct_statement="SHM is the special oscillation where acceleration is proportional to displacement and always points back toward equilibrium.",
        sim_concept="shm_condition",
        controls=[
            ("omega", "Angular frequency", "It changes how quickly the SHM cycle runs."),
            ("displacement_probe", "Probe displacement", "It tests how acceleration changes with position."),
            ("return_rule", "Return rule", "It compares proportional SHM with non-SHM behavior."),
        ],
        readouts=[
            ("acceleration_readout", "Shows the acceleration for the chosen displacement."),
            ("proportionality_check", "Shows whether the restoring rule matches SHM."),
            ("equilibrium_crossing", "Shows when the oscillator passes the center."),
        ],
        mapping=[
            "Return law = SHM condition",
            "Signed offset = displacement",
            "Back pull = restoring acceleration",
            "Cycle rate = angular frequency",
        ],
        trap="Do not call every repeated motion SHM without checking the proportional restoring rule.",
    ),
    _bp(
        slug="shm_graphs_equations",
        title="SHM Graphs and Equations",
        focus="displacement, velocity, and acceleration traces are linked views of one oscillation with fixed phase relationships",
        terms=[
            ("Phase", "Phase tells where the oscillator is in its cycle.", "It connects the different graphs."),
            ("Period", "The period is the time for one complete oscillation.", "It links the graph spacing to frequency."),
            ("Frequency", "Frequency is the number of oscillations per second.", "It is the reciprocal of the period."),
            ("Sinusoidal graph", "A sinusoidal graph is the smooth periodic trace associated with ideal SHM.", "It gives the recognizable time pattern."),
        ],
        core=[
            "Ideal SHM produces sinusoidal time graphs.",
            "Displacement, velocity, and acceleration have fixed phase relationships.",
            "Period and frequency are read from the repeating time spacing.",
            "The equations and graphs are different windows onto the same motion.",
        ],
        equation="x = x0 cos omega t and f = 1 / T",
        meaning="The displacement varies sinusoidally with time, and frequency is set by the cycle period.",
        units=["m", "s", "Hz", "rad s^-1"],
        conditions="Use for ideal SHM trace reading and equation interpretation.",
        reason="Because the oscillator follows one repeating cycle, so displacement, velocity, and acceleration traces stay phase-linked rather than becoming separate unrelated graphs.",
        contrast="The period measures the time for one cycle, while frequency measures how many cycles occur each second.",
        correct_statement="SHM graphs are most useful when displacement, velocity, and acceleration are read as phase-linked views of one oscillation.",
        sim_concept="shm_traces",
        controls=[
            ("time_window", "Time window", "It changes how much of the oscillation is visible."),
            ("frequency", "Frequency", "It changes the cycle spacing."),
            ("trace_mode", "Trace set", "It toggles between displacement, velocity, and acceleration views."),
        ],
        readouts=[
            ("period_measure", "Shows the measured period from the trace."),
            ("frequency_measure", "Shows the corresponding frequency."),
            ("phase_alignment", "Shows how the selected traces are shifted relative to one another."),
        ],
        mapping=[
            "Cycle trace = sinusoidal graph",
            "Repeat spacing = period",
            "Cycles per second = frequency",
            "Shifted trace = phase relationship",
        ],
        trap="Do not treat the displacement, velocity, and acceleration graphs as if they were unrelated signals.",
    ),
    _bp(
        slug="energy_in_shm",
        title="Energy Changes in SHM",
        focus="the oscillator swaps energy between stored stretch and kinetic motion while total energy stays constant in the ideal case",
        terms=[
            ("Kinetic energy", "Kinetic energy is the motion energy of the oscillator.", "It is largest as the oscillator passes equilibrium."),
            ("Potential energy", "Potential energy is the stored energy associated with displacement in the restoring system.", "It is largest at maximum displacement."),
            ("Total energy", "Total energy is the sum of kinetic and potential energy in the ideal oscillator.", "It stays constant when no damping is present."),
            ("Equilibrium", "The equilibrium position is where the potential-energy store is least in the simple model.", "It anchors the energy swap story."),
        ],
        core=[
            "Energy swaps continuously between kinetic and potential forms in SHM.",
            "Kinetic energy is greatest at equilibrium.",
            "Potential energy is greatest at maximum displacement.",
            "The total energy stays constant in the ideal undamped model.",
        ],
        equation="total energy = kinetic energy + potential energy",
        meaning="The energy moves between forms without changing the total in the ideal model.",
        units=["J", "m", "m s^-1"],
        conditions="Use for ideal SHM without damping or external driving.",
        reason="Because the oscillator stores energy when displaced and converts that stored energy into motion as it passes back through equilibrium, so the form changes even when the total remains constant.",
        contrast="Kinetic energy is largest at equilibrium, while potential energy is largest at maximum displacement.",
        correct_statement="SHM energy is easiest to trust when the stored-energy and motion-energy stories are tracked together through the cycle.",
        sim_concept="shm_energy_swap",
        controls=[
            ("amplitude", "Amplitude", "It changes the total energy scale of the oscillator."),
            ("mass_or_stiffness", "System setting", "It changes how the energy is shared through the motion."),
            ("position_probe", "Cycle position", "It samples the energy at different points of the oscillation."),
        ],
        readouts=[
            ("kinetic_energy", "Shows the motion-energy share."),
            ("potential_energy", "Shows the stored-energy share."),
            ("total_energy", "Shows the total energy of the ideal oscillator."),
        ],
        mapping=[
            "Stretch store = potential energy",
            "Through-center rush = kinetic energy",
            "Full ledger = total energy",
            "Cycle probe = sampled oscillator position",
        ],
        trap="Do not say the energy is used up at equilibrium just because the displacement there is zero.",
    ),
    _bp(
        slug="forced_resonance",
        title="Forced Oscillations and Resonance",
        focus="a driven oscillator responds most strongly when the driving rhythm matches its natural timing",
        terms=[
            ("Forced oscillation", "A forced oscillation is maintained by an external periodic driving force.", "It separates self-return from continued driving."),
            ("Natural frequency", "The natural frequency is the frequency at which the system oscillates most readily on its own.", "It sets the preferred timing of the oscillator."),
            ("Resonance", "Resonance is the large-amplitude response when the driving frequency matches the natural frequency closely.", "It is the key amplification idea."),
            ("Driving frequency", "The driving frequency is the frequency of the external periodic force.", "It is compared against the system's own timing."),
        ],
        core=[
            "Forced oscillations are maintained by an external driver.",
            "The strongest response occurs near the natural frequency.",
            "Resonance is a response condition, not a separate kind of force.",
            "Amplitude depends on how closely the drive matches the natural timing and on the damping present.",
        ],
        equation="largest response occurs when driving frequency is near natural frequency",
        meaning="Matching the system's own timing produces the biggest steady oscillation.",
        units=["Hz", "amplitude"],
        conditions="Use for driven oscillators where the long-term response to a periodic driver is considered.",
        reason="Because the oscillator absorbs energy most efficiently when the repeated pushes arrive in step with its natural return cycle.",
        contrast="The natural frequency belongs to the system itself, while the driving frequency is set by the external source.",
        correct_statement="Resonance is the strong-response condition that appears when the external drive matches the oscillator's natural timing.",
        sim_concept="resonance_drive",
        controls=[
            ("driving_frequency", "Driving frequency", "It changes how closely the driver matches the natural timing."),
            ("drive_strength", "Drive strength", "It changes how much energy is supplied each cycle."),
            ("damping", "Damping", "It changes how sharply the resonance peak appears."),
        ],
        readouts=[
            ("response_amplitude", "Shows the steady oscillation size."),
            ("frequency_match", "Shows how close the drive is to the natural frequency."),
            ("resonance_status", "Shows whether the system is near resonance."),
        ],
        mapping=[
            "Driver pulse = external periodic force",
            "Own beat = natural frequency",
            "Beat match = resonance condition",
            "Response size = oscillation amplitude",
        ],
        trap="Do not describe resonance as a mysterious extra force instead of a frequency-match response.",
    ),
    _bp(
        slug="damping_applications",
        title="Damping and Oscillation Applications",
        focus="real oscillators lose energy to resistance, and the useful design question is how much damping the system should have",
        terms=[
            ("Damping", "Damping is the removal of oscillation energy by resistive effects.", "It explains why real oscillations often fade."),
            ("Underdamped", "Underdamped means the system still oscillates while the amplitude decreases.", "It is the repeated-but-fading case."),
            ("Critically damped", "Critically damped means the system returns to equilibrium quickly without oscillating.", "It is often the design target for fast settling."),
            ("Overdamped", "Overdamped means the system returns without oscillating but more slowly than the critically damped case.", "It contrasts slow return with oscillatory fading."),
        ],
        core=[
            "Damping removes energy from the oscillator.",
            "Different damping levels produce different return behaviors.",
            "Underdamped, critically damped, and overdamped responses serve different design goals.",
            "Applications are best explained by matching the damping style to the job.",
        ],
        equation="greater damping reduces amplitude growth and shapes settling behavior",
        meaning="Resistance changes both the size of oscillations and how the system returns to equilibrium.",
        units=["qualitative damping level", "settling time"],
        conditions="Use for real oscillators where resistive energy loss matters.",
        reason="Because real systems lose energy to resistive processes, so the useful question becomes how quickly and smoothly the system should settle rather than whether it oscillates forever.",
        contrast="Underdamped systems still oscillate as they fade, while critically damped systems return fastest without overshooting.",
        correct_statement="Damping is easiest to understand when it is treated as an energy-loss setting that shapes the response style of the oscillator.",
        sim_concept="damping_responses",
        controls=[
            ("damping_level", "Damping level", "It changes whether the system is underdamped, critically damped, or overdamped."),
            ("initial_displacement", "Initial displacement", "It sets the starting disturbance."),
            ("application_mode", "Application target", "It compares designs such as instruments, suspensions, or door closers."),
        ],
        readouts=[
            ("response_type", "Shows the damping regime for the chosen setting."),
            ("settling_trace", "Shows how the amplitude changes with time."),
            ("application_fit", "Shows which practical use best matches the response."),
        ],
        mapping=[
            "Energy leak = damping",
            "Fading swing = underdamped response",
            "Fast settle = critically damped response",
            "Slow creep back = overdamped response",
        ],
        trap="Do not assume more damping is always better without asking what response the application actually needs.",
    ),
]

A5_MODULE_DOC, A5_LESSONS, A5_SIM_LABS = _module(
    module_id="A5",
    title=A5_MODULE_TITLE,
    content_version=A5_CONTENT_VERSION,
    sequence=22,
    model_name="Swing-Return Model of Oscillations",
    description=A5_MODULE_DESCRIPTION,
    mastery_outcomes=A5_MASTERY_OUTCOMES,
    lessons=_A5_BLUEPRINTS,
)
_upgrade_phase3_lessons("A5", A5_LESSONS, _A5_BLUEPRINTS)


def revised_phase3_bundle(module_id: str) -> Tuple[str, Dict[str, Any], List[Tuple[str, Dict[str, Any]]], List[Tuple[str, Dict[str, Any]]]]:
    bundles = {
        "A1": (A1_CONTENT_VERSION, A1_MODULE_DOC, A1_LESSONS, A1_SIM_LABS),
        "A2": (A2_CONTENT_VERSION, A2_MODULE_DOC, A2_LESSONS, A2_SIM_LABS),
        "A3": (A3_CONTENT_VERSION, A3_MODULE_DOC, A3_LESSONS, A3_SIM_LABS),
        "A4": (A4_CONTENT_VERSION, A4_MODULE_DOC, A4_LESSONS, A4_SIM_LABS),
        "A5": (A5_CONTENT_VERSION, A5_MODULE_DOC, A5_LESSONS, A5_SIM_LABS),
    }
    normalized = str(module_id or "").strip().upper()
    if normalized not in bundles:
        raise KeyError(f"Unsupported phase-3 module: {module_id}")
    content_version, module_doc, lessons, sim_labs = bundles[normalized]
    return content_version, deepcopy(module_doc), deepcopy(lessons), deepcopy(sim_labs)


def seed_module_cli(module_id: str) -> None:
    try:
        from scripts.module_asset_pipeline import default_asset_root, render_module_assets
        from scripts.seed_m1_module import get_project_id, init_firebase, print_preview, upsert_doc
    except ModuleNotFoundError:
        from module_asset_pipeline import default_asset_root, render_module_assets
        from seed_m1_module import get_project_id, init_firebase, print_preview, upsert_doc

    normalized = str(module_id or "").strip().upper()
    parser = argparse.ArgumentParser(description=f"Seed revised phase-3 module {normalized}")
    parser.add_argument("--project", default=None)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--compile-assets", action="store_true")
    parser.add_argument("--asset-root", default="")
    parser.add_argument("--public-base", default="/lesson_assets")
    args = parser.parse_args()

    project = get_project_id(args.project)
    asset_root = args.asset_root or default_asset_root()
    module_doc, lesson_pairs, sim_pairs = revised_phase3_bundle(normalized)[1:]

    if args.compile_assets:
        render_module_assets(lesson_pairs, sim_pairs, asset_root=asset_root, public_base=args.public_base)

    print_preview(module_doc, lesson_pairs, sim_pairs)
    db = init_firebase(project)
    plan: List[Tuple[str, str]] = [("modules", normalized)]
    plan.extend(("lessons", doc_id) for doc_id, _ in lesson_pairs)
    plan.extend(("sim_labs", doc_id) for doc_id, _ in sim_pairs)

    for collection, doc_id in plan:
        if collection == "modules":
            upsert_doc(db, collection, doc_id, module_doc, bool(args.apply))
        elif collection == "lessons":
            payload = next(payload for payload_id, payload in lesson_pairs if payload_id == doc_id)
            upsert_doc(db, collection, doc_id, payload, bool(args.apply))
        else:
            payload = next(payload for payload_id, payload in sim_pairs if payload_id == doc_id)
            upsert_doc(db, collection, doc_id, payload, bool(args.apply))
