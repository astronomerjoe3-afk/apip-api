from __future__ import annotations

import argparse
from copy import deepcopy
from typing import Any, Dict, List, Sequence, Tuple

try:
    from scripts.lesson_authoring_contract import AUTHORING_STANDARD_V3
    from scripts.module_asset_pipeline import default_asset_root, render_module_assets
    from scripts.nextgen_module_builder import build_nextgen_module_bundle
except ModuleNotFoundError:
    from lesson_authoring_contract import AUTHORING_STANDARD_V3
    from module_asset_pipeline import default_asset_root, render_module_assets
    from nextgen_module_builder import build_nextgen_module_bundle

try:
    from scripts.seed_m1_module import get_project_id, init_firebase, print_preview, upsert_doc
except ModuleNotFoundError:
    from seed_m1_module import get_project_id, init_firebase, print_preview, upsert_doc


M13_MODULE_ID = "M13"
M13_CONTENT_VERSION = "20260321_m13_core_vault_v1"
M13_MODULE_TITLE = "Radioactivity"
M13_ALLOWLIST = [
    "nucleus_electron_confusion",
    "proton_identity_confusion",
    "isotope_element_confusion",
    "radioactivity_outer_shell_confusion",
    "alpha_beta_gamma_mixup",
    "gamma_changes_numbers_confusion",
    "beta_mass_number_confusion",
    "radiation_penetration_order_confusion",
    "half_life_fixed_timer_confusion",
    "half_life_linear_drop_confusion",
    "background_zero_confusion",
    "background_means_contamination_confusion",
    "decay_equation_balance_confusion",
]


def safe_tags(tags: Sequence[str]) -> List[str]:
    allowed = set(M13_ALLOWLIST)
    return [str(tag) for tag in tags if str(tag) in allowed]


def mcq(qid: str, prompt: str, choices: Sequence[str], answer_index: int, hint: str, tags: Sequence[str], *, skill_tags: Sequence[str]) -> Dict[str, Any]:
    return {
        "id": qid,
        "question_id": qid,
        "kind": "mcq",
        "type": "mcq",
        "prompt": prompt,
        "choices": list(choices),
        "answer_index": answer_index,
        "hint": hint,
        "feedback": [hint for _ in choices],
        "misconception_tags": safe_tags(tags),
        "skill_tags": [str(tag) for tag in skill_tags],
    }


def short(
    qid: str,
    prompt: str,
    accepted_answers: Sequence[str],
    hint: str,
    tags: Sequence[str],
    *,
    skill_tags: Sequence[str],
    acceptance_rules: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    item = {
        "id": qid,
        "question_id": qid,
        "kind": "short",
        "type": "short",
        "prompt": prompt,
        "accepted_answers": list(accepted_answers),
        "hint": hint,
        "feedback": [hint],
        "misconception_tags": safe_tags(tags),
        "skill_tags": [str(tag) for tag in skill_tags],
    }
    if acceptance_rules:
        item["acceptance_rules"] = deepcopy(acceptance_rules)
    return item


def acceptance_groups(*groups: Sequence[str]) -> Dict[str, Any]:
    return {"phrase_groups": [list(group) for group in groups]}


def prompt_block(prompt: str, hint: str) -> Dict[str, str]:
    return {"prompt": prompt, "hint": hint}


def relation(equation: str, meaning: str, units: Sequence[str], conditions: str) -> Dict[str, Any]:
    return {"equation": equation, "meaning": meaning, "units": list(units), "conditions": conditions}


def representation(kind: str, purpose: str) -> Dict[str, str]:
    return {"kind": kind, "purpose": purpose}


def worked(prompt: str, steps: Sequence[str], final_answer: str, answer_reason: str, why_it_matters: str) -> Dict[str, Any]:
    return {"prompt": prompt, "steps": list(steps), "final_answer": final_answer, "answer_reason": answer_reason, "why_it_matters": why_it_matters}


def visual(
    asset_id: str,
    concept: str,
    title: str,
    purpose: str,
    caption: str,
    *,
    template: str = "auto",
    meta: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    diagram_type_map = {
        "core_vault_identity": "vault_house",
        "same_badge_vaults": "same_badge_vaults",
        "escape_signals": "escape_signals",
        "settle_span": "half_life_crowd",
        "ambient_buzz": "ambient_buzz",
        "vault_ledger": "decay_ledger",
    }
    resolved_meta = deepcopy(meta or {})
    resolved_template = template
    if resolved_template == "auto" and concept in diagram_type_map:
        resolved_template = "radioactivity_diagram"
    if concept in diagram_type_map and "diagram_type" not in resolved_meta:
        resolved_meta["diagram_type"] = diagram_type_map[concept]
    return {
        "asset_id": asset_id,
        "concept": concept,
        "phase_key": "analogical_grounding",
        "title": title,
        "purpose": purpose,
        "caption": caption,
        "template": resolved_template,
        "meta": resolved_meta,
    }


def animation(asset_id: str, concept: str, title: str, description: str) -> Dict[str, Any]:
    return {"asset_id": asset_id, "concept": concept, "phase_key": "analogical_grounding", "title": title, "description": description, "duration_sec": 8}


def extra_section(heading: str, body: str, check_for_understanding: str) -> Dict[str, str]:
    return {"heading": heading, "body": body, "check_for_understanding": check_for_understanding}


def scaffold(core_idea: str, reasoning: str, check: str, trap: str, analogy_body: str, analogy_check: str, extras: Sequence[Dict[str, str]]) -> Dict[str, Any]:
    return {"core_idea": core_idea, "reasoning": reasoning, "check_for_understanding": check, "common_trap": trap, "analogy_bridge": {"body": analogy_body, "check_for_understanding": analogy_check}, "extra_sections": list(extras)}


def assessment_targets() -> Dict[str, Any]:
    return {"diagnostic_pool_min": 8, "concept_gate_pool_min": 6, "mastery_pool_min": 8, "fresh_attempt_policy": "Prefer unseen lesson-owned questions in diagnostic, concept-gate, and mastery before repeating any previous stem."}


def visual_checks(topic: str) -> List[str]:
    return [
        f"The main {topic} labels stay fully visible on desktop and mobile.",
        "Badge, stone, orbit, and radiation labels stay separated so the nuclear relationships do not collapse into one blur.",
        "Population, shielding, and ledger labels remain readable without overlapping the main diagram geometry.",
    ]


def core_vault_map(focus: str) -> Dict[str, Any]:
    return {
        "model_name": "Core-Vault Model",
        "focus": focus,
        "comparison": f"The Core-Vault world keeps atomic structure, isotopes, radiation, half-life, background radiation, and decay equations inside one story while {focus}.",
        "mapping": [
            "Vault-house -> atom",
            "Core Vault -> nucleus",
            "Orbit Ring -> electron region",
            "Identity Badges -> protons",
            "Balance Stones -> neutrons",
            "Same-Badge Vaults -> isotopes",
            "Restless Vault -> unstable nucleus / radioisotope",
            "Chunk Burst -> alpha radiation",
            "Switch Spark -> beta radiation",
            "Glow Flash -> gamma radiation",
            "Settle Span -> half-life",
            "Ambient Buzz -> background radiation",
            "Vault Ledger -> decay equation bookkeeping",
        ],
        "limit": "The model keeps the nuclear relationships coherent, but learners still need the formal terms nucleus, isotope, alpha, beta, gamma, half-life, and decay equation.",
        "prediction_prompt": f"Use the Core-Vault model to predict what should happen when {focus}.",
    }


def sim_contract(asset_id: str, concept: str, focus_prompt: str, baseline_case: str, comparison_tasks: Sequence[str], watch_for: str, takeaway: str, controls: Sequence[Tuple[str, str, str]], readouts: Sequence[Tuple[str, str]]) -> Dict[str, Any]:
    return {"asset_id": asset_id, "concept": concept, "focus_prompt": focus_prompt, "baseline_case": baseline_case, "comparison_tasks": list(comparison_tasks), "watch_for": watch_for, "takeaway": takeaway, "controls": [{"variable": a, "label": b, "why_it_matters": c} for a, b, c in controls], "readouts": [{"label": a, "meaning": b} for a, b in readouts]}


def contract(*, concept_targets: Sequence[str], core_concepts: Sequence[str], prerequisite_lessons: Sequence[str], misconception_focus: Sequence[str], formulas: Sequence[Dict[str, Any]], representations: Sequence[Dict[str, Any]], analogy_map: Dict[str, Any], worked_examples: Sequence[Dict[str, Any]], visual_assets: Sequence[Dict[str, Any]], animation_assets: Sequence[Dict[str, Any]], simulation_contract: Dict[str, Any], reflection_prompts: Sequence[str], mastery_skills: Sequence[str], variation_plan: Dict[str, str], scaffold_support: Dict[str, Any], visual_clarity_checks: Sequence[str]) -> Dict[str, Any]:
    return {"concept_targets": list(concept_targets), "core_concepts": list(core_concepts), "prerequisite_lessons": list(prerequisite_lessons), "misconception_focus": safe_tags(misconception_focus), "formulas": [deepcopy(item) for item in formulas], "representations": [deepcopy(item) for item in representations], "analogy_map": deepcopy(analogy_map), "worked_examples": [deepcopy(item) for item in worked_examples], "visual_assets": [deepcopy(item) for item in visual_assets], "animation_assets": [deepcopy(item) for item in animation_assets], "simulation_contract": deepcopy(simulation_contract), "reflection_prompts": list(reflection_prompts), "mastery_skills": list(mastery_skills), "variation_plan": deepcopy(variation_plan), "assessment_bank_targets": assessment_targets(), "scaffold_support": deepcopy(scaffold_support), "visual_clarity_checks": list(visual_clarity_checks)}


def sim(lab_id: str, title: str, description: str, instructions: Sequence[str], outcomes: Sequence[str], fields: Sequence[str], depth: str) -> Dict[str, Any]:
    return {"lab_id": lab_id, "title": title, "description": description, "instructions": list(instructions), "outcomes": list(outcomes), "fields": list(fields), "depth": depth}


def lesson_spec(lesson_id: str, title: str, sim_meta: Dict[str, Any], diagnostic: Sequence[Dict[str, Any]], analogy_text: str, commitment_prompt: str, micro_prompts: Sequence[Dict[str, str]], inquiry: Sequence[Dict[str, str]], recon_prompts: Sequence[str], capsule_prompt: str, capsule_checks: Sequence[Dict[str, Any]], transfer: Sequence[Dict[str, Any]], contract_payload: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": lesson_id, "title": title, "sim": deepcopy(sim_meta), "diagnostic": list(diagnostic), "analogy_text": analogy_text, "commitment_prompt": commitment_prompt, "micro_prompts": list(micro_prompts), "inquiry": list(inquiry), "recon_prompts": list(recon_prompts), "capsule_prompt": capsule_prompt, "capsule_checks": list(capsule_checks), "transfer": list(transfer), "contract": deepcopy(contract_payload)}


def vault_house_lesson() -> Dict[str, Any]:
    d = [
        mcq("M13L1_D1", "In the Core-Vault model, the Core Vault stands for the...", ["nucleus", "electron shell", "whole atom", "background detector"], 0, "Radioactivity happens in the nucleus.", ["nucleus_electron_confusion"], skill_tags=["identify_nucleus"]),
        mcq("M13L1_D2", "Identity Badges stand for...", ["protons", "neutrons", "electrons", "gamma rays"], 0, "Badge count fixes the element.", ["proton_identity_confusion"], skill_tags=["proton_identity"]),
        mcq("M13L1_D3", "Balance Stones stand for...", ["neutrons", "protons", "electrons", "ions"], 0, "Neutrons affect isotope and stability without changing the element.", ["proton_identity_confusion"], skill_tags=["neutron_role"]),
        mcq("M13L1_D4", "The Orbit Ring stands for the atom's...", ["electron region", "nucleus", "mass number", "half-life"], 0, "Electrons are outside the nucleus.", ["nucleus_electron_confusion"], skill_tags=["electron_region"]),
        mcq("M13L1_D5", "What fixes the element's identity?", ["the number of protons in the nucleus", "the number of electrons only", "the color of the radiation", "the half-life"], 0, "Element identity follows proton number.", ["proton_identity_confusion"], skill_tags=["proton_identity"]),
        mcq("M13L1_D6", "If an atom loses one electron but keeps the same proton count, the element...", ["stays the same", "becomes a different element", "must become radioactive", "becomes an isotope"], 0, "Changing electrons does not change proton number.", ["nucleus_electron_confusion", "proton_identity_confusion"], skill_tags=["electron_region"]),
        short("M13L1_D7", "Why is radioactivity a Core-Vault event rather than an Orbit-Ring event?", ["Because radioactivity comes from changes in the nucleus, not from the outer electrons.", "Because the unstable nucleus changes and emits radiation, while the outer electron region is not the source of radioactivity."], "Use nucleus-not-electron language.", ["radioactivity_outer_shell_confusion"], skill_tags=["nuclear_change"], acceptance_rules=acceptance_groups(["nucleus", "core vault"], ["not", "rather than"], ["electron", "orbit ring", "outer"])),
        short("M13L1_D8", "What do Identity Badges do in the model?", ["They set the element's identity because they stand for protons.", "They fix which element the atom is by giving the proton count."], "Connect badges to proton number and identity.", ["proton_identity_confusion"], skill_tags=["proton_identity"], acceptance_rules=acceptance_groups(["badge", "identity"], ["proton"], ["element", "fix", "same kind"])),
    ]
    c = [
        short("M13L1_C1", "How would you describe an atom using the Core-Vault model?", ["An atom is a vault-house with a central Core Vault and an outer Orbit Ring.", "The atom has a central nucleus and an outer electron region in the Core-Vault model."], "Name both the center and the outer region.", ["nucleus_electron_confusion"], skill_tags=["identify_nucleus"], acceptance_rules=acceptance_groups(["core vault", "nucleus"], ["orbit ring", "electron region", "outer"])),
        mcq("M13L1_C2", "Which statement is strongest?", ["The nucleus holds the protons and neutrons.", "The orbit ring holds the protons.", "Electrons decide the element.", "Background radiation sets the badge count."], 0, "The nucleus contains protons and neutrons.", ["nucleus_electron_confusion", "proton_identity_confusion"], skill_tags=["identify_nucleus"]),
        mcq("M13L1_C3", "Which formal quantity is the proton number?", ["Z", "A", "gamma", "T"], 0, "Z is the atomic number.", ["proton_identity_confusion"], skill_tags=["atomic_number"]),
        short("M13L1_C4", "Why does changing the badge count change the element itself?", ["Because the proton number defines the element, so changing it gives a different element.", "Because the element's identity is fixed by its number of protons."], "Use proton-number identity language.", ["proton_identity_confusion"], skill_tags=["atomic_number"], acceptance_rules=acceptance_groups(["proton", "badge"], ["defines", "fixes", "identity"], ["different element", "changes the element"])),
        mcq("M13L1_C5", "Mass number A tells you the total number of...", ["protons and neutrons", "electrons only", "radiation types", "unstable atoms only"], 0, "Mass number counts nucleons.", ["proton_identity_confusion"], skill_tags=["mass_number"]),
        short("M13L1_C6", "Why is it weak to say radioactivity comes from the outer electrons?", ["Because radioactivity is a nuclear change, so the source is the nucleus rather than the outer electron region.", "Because unstable nuclei emit radiation; the outer electrons are not the origin of the decay."], "Keep the source of decay inside the nucleus.", ["radioactivity_outer_shell_confusion"], skill_tags=["nuclear_change"], acceptance_rules=acceptance_groups(["radioactivity", "decay"], ["nucleus", "nuclear", "core vault"], ["not", "rather than"], ["electrons", "orbit ring", "outer"])),
    ]
    t = [
        mcq("M13L1_M1", "An atom has Z = 8. What fixes its identity?", ["8 protons", "8 neutrons", "8 electrons only", "8 gamma rays"], 0, "Z is proton number.", ["proton_identity_confusion"], skill_tags=["atomic_number"]),
        short("M13L1_M2", "An atom has mass number 19 and proton number 9. How many neutrons does it have?", ["10", "10 neutrons"], "Use neutrons = A - Z.", ["proton_identity_confusion"], skill_tags=["neutron_count"], acceptance_rules=acceptance_groups(["10"])),
        mcq("M13L1_M3", "Which change leaves the element unchanged?", ["changing the number of electrons only", "changing the number of protons", "changing proton and neutron numbers together", "changing badge count"], 0, "Element identity depends on proton number.", ["nucleus_electron_confusion", "proton_identity_confusion"], skill_tags=["electron_region"]),
        mcq("M13L1_M4", "Which pair belongs in the nucleus?", ["protons and neutrons", "electrons and gamma rays", "electrons and protons only", "half-life and background"], 0, "The nucleus holds protons and neutrons.", ["nucleus_electron_confusion"], skill_tags=["identify_nucleus"]),
        short("M13L1_M5", "Why is the Orbit Ring not where radioactivity begins?", ["Because radioactivity begins when the unstable nucleus changes, not when the electrons move around the atom.", "Because the decay source is the Core Vault, not the outer electron region."], "Keep nucleus and electrons separate.", ["radioactivity_outer_shell_confusion"], skill_tags=["nuclear_change"], acceptance_rules=acceptance_groups(["radioactivity", "decay"], ["nucleus", "core vault"], ["not", "rather than"], ["electrons", "orbit ring"])),
        mcq("M13L1_M6", "Which notation pair is correct?", ["Z = proton number and A = proton + neutron total", "Z = neutron number and A = electron number", "Z = gamma number and A = half-life", "Z = orbit number and A = badge color"], 0, "Keep formal notation tied to the nucleus.", ["proton_identity_confusion"], skill_tags=["mass_number"]),
        short("M13L1_M7", "A learner says, 'the electrons decide the element because they are on the outside.' What is the correction?", ["The element is decided by the proton count in the nucleus, not by the outer electrons.", "Identity lives in the Core Vault because the proton number fixes the element."], "Correct element identity using proton language.", ["nucleus_electron_confusion", "proton_identity_confusion"], skill_tags=["proton_identity"], acceptance_rules=acceptance_groups(["proton", "badge"], ["nucleus", "core vault"], ["element", "identity", "fixes"], ["not", "rather than"], ["electrons", "outer"])),
        mcq("M13L1_M8", "Best summary of Lesson 1:", ["the nucleus holds protons and neutrons, and proton count fixes the element", "electrons create radioactivity and fix the element", "background radiation decides the mass number", "half-life belongs to the orbit ring"], 0, "That keeps the nuclear structure story intact.", ["nucleus_electron_confusion", "proton_identity_confusion"], skill_tags=["identify_nucleus"]),
    ]
    return lesson_spec(
        "M13_L1",
        "Build the Vault-House",
        sim("m13_core_vault_lab", "Core Vault lab", "Build an atom in the Core-Vault world and separate nucleus, electrons, badges, and stones.", ["Build one vault-house.", "Change electron count without changing badge count.", "Compare proton number with mass number."], ["Describe atomic structure using nucleus and electron region.", "Explain why proton count fixes element identity.", "Explain why radioactivity is a nuclear event."], ["proton_count", "neutron_count", "electron_count", "identity_readout"], "Atomic structure and identity reasoning."),
        d,
        "Every vault-house has a dense Core Vault and an outer Orbit Ring. Identity Badges in the Core Vault fix the element, while Balance Stones help shape mass and stability.",
        "Before naming the radiation story, decide which part of the vault-house you are talking about: the Core Vault or the Orbit Ring.",
        [prompt_block("What part of the vault-house fixes identity?", "The Core Vault, because that is where the badges live."), prompt_block("What lives in the Orbit Ring?", "The electron region.")],
        [prompt_block("Keep the badge count fixed and change the electron count.", "The element should stay the same."), prompt_block("Now compare proton number with total nucleon number.", "Badge count fixes identity, while total count includes stones too.")],
        ["Explain why proton count fixes the element even when electron count changes.", "Explain why radioactivity belongs to the Core Vault story rather than the Orbit Ring story."],
        "Use the Core-Vault model to keep nucleus and electron ideas separate before the isotope and radiation lessons begin.",
        c,
        t,
        contract(
            concept_targets=["Describe the atom as a nucleus with an outer electron region.", "Explain that proton count fixes the element's identity.", "Use atomic number and mass number language for the nucleus."],
            core_concepts=["The nucleus contains protons and neutrons.", "Proton number fixes which element the atom is.", "Mass number counts protons plus neutrons.", "Radioactivity is a nuclear event, not an electron-shell event."],
            prerequisite_lessons=["F1_L1"],
            misconception_focus=["nucleus_electron_confusion", "proton_identity_confusion", "radioactivity_outer_shell_confusion"],
            formulas=[relation("Z = proton number", "Atomic number Z is the number of protons and fixes the element.", ["count"], "Use when identifying the element."), relation("A = proton number + neutron number", "Mass number A counts all nucleons in the nucleus.", ["count"], "Use when comparing nuclei and isotopes.")],
            representations=[representation("words", "Explains how nucleus, electrons, protons, and neutrons fit together."), representation("diagram", "Shows the Core Vault and Orbit Ring as different parts of one atom."), representation("formula", "Introduces atomic number and mass number language.")],
            analogy_map=core_vault_map("the class is building one vault-house before deciding what fixes identity"),
            worked_examples=[worked("A nucleus has proton number 8 and mass number 16. What does each number tell you?", ["Read Z as the proton count.", "Read A as the total proton-plus-neutron count.", "State what part fixes identity."], "Z = 8 fixes the element, and A = 16 tells the total nucleon count.", "Atomic number tells identity while mass number tells total nucleons.", "This establishes the two nuclear numbers before isotopes appear."), worked("An atom loses one electron. Does it become a different element?", ["Check whether the proton count changed.", "Notice the change happened outside the nucleus.", "State the identity rule."], "No. It stays the same element because the proton count is unchanged.", "Element identity depends on proton number, not outer electrons.", "This blocks the common idea that any particle change changes the element."), worked("Mass number is 19 and proton number is 9. How many neutrons are there?", ["Use neutrons = A - Z.", "Substitute 19 and 9.", "State the neutron count."], "10 neutrons", "Mass number includes both protons and neutrons, so subtract protons to find neutrons.", "This readies students for isotope questions.")],
            visual_assets=[visual("m13-l1-vault-house", "core_vault_identity", "Build the Vault-House", "Shows the Core Vault, Orbit Ring, badges, and stones in one atom.", "Identity, balance, and outer-electron labels must stay separate and readable.")],
            animation_assets=[animation("m13-l1-vault-build", "core_vault_identity", "Vault-house build", "Shows a vault-house assembling from Orbit Ring, Core Vault, badges, and stones.")],
            simulation_contract=sim_contract("m13-l1-core-vault-lab", "core_vault_identity", "How does the Core-Vault model separate identity, mass, and the outer electron region?", "Start with one vault-house and label the Core Vault and Orbit Ring before changing any counts.", ["Keep badge count fixed while changing electron count.", "Keep electron count fixed while changing badge count.", "Compare atomic number with mass number."], "Do not let the outer electron region take over the nuclear identity story.", "Identity lives in badge count inside the Core Vault.", [("proton_count", "Badge count", "Sets the element identity."), ("neutron_count", "Stone count", "Changes total nucleon count without changing the element."), ("electron_count", "Orbit count", "Keeps the outer region visible but separate.")], [("Element identity", "Shows which element the badge count gives."), ("Mass number", "Shows total nucleon count."), ("Nuclear focus", "Reminds the learner that radioactivity belongs in the nucleus.")]),
            reflection_prompts=["What part of the vault-house determines the element's identity?", "Why is radioactivity a Core-Vault event rather than an Orbit-Ring event?"],
            mastery_skills=["identify_nucleus", "proton_identity", "electron_region", "mass_number", "neutron_count"],
            variation_plan={"diagnostic": "Fresh attempts rotate between nucleus-electron distinction, badge identity, and A-versus-Z stems.", "concept_gate": "Concept checks vary between proton-identity and nuclear-versus-electron explanations.", "mastery": "Mastery mixes atomic notation, neutron counting, and explanation prompts before repeating any stem."},
            scaffold_support=scaffold("The Core Vault keeps identity, while the Orbit Ring sits outside the nuclear change story.", "Name the part first: nucleus or electron region. Then decide whether the question is about identity, mass, or radioactivity.", "If the badge count stays fixed, should the element change?", "Do not let electron changes replace proton-number identity.", "The vault-house model works because the badges stay in the Core Vault and decide the house type.", "Which part of the vault-house would you inspect first if a question asks about element identity?", [extra_section("Identity versus total count", "The element is fixed by badge count, while the total nucleon count combines badges and stones.", "Why can two nuclei have the same element identity but different total count?"), extra_section("Nuclear story versus electron story", "Electrons belong in the Orbit Ring, but radioactivity and isotope language belong in the nucleus.", "Why is an outer-electron change not the same as nuclear decay?")]),
            visual_clarity_checks=visual_checks("vault-house"),
        ),
    )


def isotope_lesson() -> Dict[str, Any]:
    d = [
        mcq("M13L2_D1", "Same-Badge Vaults stand for...", ["isotopes", "ions", "electrons", "gamma rays"], 0, "Same proton count but different neutron count gives isotopes.", ["isotope_element_confusion"], skill_tags=["identify_isotopes"]),
        mcq("M13L2_D2", "Two nuclei are isotopes of the same element if they have the same number of...", ["protons", "neutrons", "electrons", "half-lives"], 0, "Isotopes keep the same proton number.", ["isotope_element_confusion"], skill_tags=["identify_isotopes"]),
        mcq("M13L2_D3", "If the badge count is unchanged but the stone count changes, the atom becomes...", ["a different isotope of the same element", "a different element", "a gamma ray", "a background source only"], 0, "Neutron change gives a different isotope, not a different element.", ["isotope_element_confusion"], skill_tags=["identify_isotopes"]),
        mcq("M13L2_D4", "A restless vault is best described as...", ["an unstable nucleus likely to decay", "an electron leaving the atom", "a zero-background detector", "a stable isotope only"], 0, "Radioisotopes have unstable nuclei.", ["radioactivity_outer_shell_confusion"], skill_tags=["radioisotope"]),
        mcq("M13L2_D5", "Carbon-12 and carbon-14 are the same element because they have the same...", ["proton number", "neutron number", "mass number", "half-life"], 0, "Same proton number means same element.", ["isotope_element_confusion"], skill_tags=["identify_isotopes"]),
        mcq("M13L2_D6", "What can differ between isotopes of the same element?", ["neutron number", "proton number", "element identity", "the existence of the nucleus"], 0, "Neutron count can change while proton count stays fixed.", ["isotope_element_confusion"], skill_tags=["neutron_count"]),
        short("M13L2_D7", "Why are two same-badge vaults still the same element?", ["Because the proton count is the same, so the element identity stays the same even if the neutron count changes.", "Because isotopes keep the same atomic number even when their neutron numbers differ."], "Use same-proton-number language.", ["isotope_element_confusion"], skill_tags=["identify_isotopes"], acceptance_rules=acceptance_groups(["same", "proton", "badge"], ["element", "identity", "atomic number"], ["same"])),
        short("M13L2_D8", "What makes one isotope stable and another restless?", ["A different neutron balance can make one nucleus stable and another unstable.", "Different neutron numbers can change nuclear stability even when the proton number is the same."], "Connect stability to nuclear balance, not to electron shells.", ["radioactivity_outer_shell_confusion", "isotope_element_confusion"], skill_tags=["radioisotope"], acceptance_rules=acceptance_groups(["neutron", "stone"], ["stable", "unstable", "restless"], ["same proton", "same badge", "same element"])),
    ]
    c = [
        short("M13L2_C1", "How would you define isotopes in one sentence?", ["Isotopes are atoms of the same element with the same proton number but different neutron numbers.", "They are same-element atoms with the same atomic number and different neutron counts."], "Use same-proton-number and different-neutron-number language.", ["isotope_element_confusion"], skill_tags=["identify_isotopes"], acceptance_rules=acceptance_groups(["same", "element", "proton", "atomic number"], ["different", "neutron", "stone"])),
        mcq("M13L2_C2", "Which formal quantity stays the same for isotopes of one element?", ["atomic number Z", "mass number A", "neutron number only", "background count"], 0, "Z stays the same for isotopes.", ["isotope_element_confusion"], skill_tags=["atomic_number"]),
        mcq("M13L2_C3", "If A = 23 and Z = 11, the neutron number is...", ["12", "11", "23", "34"], 0, "Use N = A - Z.", ["isotope_element_confusion"], skill_tags=["neutron_count"]),
        short("M13L2_C4", "Why is 'different neutrons means different element' weak?", ["Because the element is fixed by proton number, not neutron number.", "Because changing neutrons changes the isotope but not the element identity."], "Keep proton number as the identity rule.", ["isotope_element_confusion", "proton_identity_confusion"], skill_tags=["atomic_number"], acceptance_rules=acceptance_groups(["proton", "badge", "atomic number"], ["fixes", "defines", "identity"], ["not", "rather than"], ["neutron", "stone"])),
        mcq("M13L2_C5", "Which pair could be isotopes?", ["same Z, different A", "different Z, same A", "different Z, different A only", "same A, same Z only"], 0, "Isotopes keep the same atomic number.", ["isotope_element_confusion"], skill_tags=["identify_isotopes"]),
        short("M13L2_C6", "Why does the Core-Vault model call isotopes same-badge vaults?", ["Because the badge count stays the same while the stone count can change.", "Because isotopes keep the same proton number even when neutron count differs."], "Connect same-badge language to proton number.", ["isotope_element_confusion"], skill_tags=["identify_isotopes"], acceptance_rules=acceptance_groups(["same badge", "same proton", "same atomic number"], ["stone", "neutron"], ["change", "different"])),
    ]
    t = [
        mcq("M13L2_M1", "Which pair is definitely not isotopes of the same element?", ["nuclei with different proton numbers", "nuclei with the same proton number", "same-badge vaults", "same Z, different neutron number"], 0, "Different proton number means different element.", ["isotope_element_confusion"], skill_tags=["identify_isotopes"]),
        short("M13L2_M2", "An atom has A = 37 and Z = 17. How many neutrons does it have?", ["20", "20 neutrons"], "Neutrons = A - Z.", ["isotope_element_confusion"], skill_tags=["neutron_count"], acceptance_rules=acceptance_groups(["20"])),
        mcq("M13L2_M3", "Two nuclei both have Z = 6, but one has A = 12 and the other A = 14. They are...", ["isotopes of carbon", "different elements", "different gamma rays", "identical nuclei"], 0, "Same proton number and different mass number means isotopes.", ["isotope_element_confusion"], skill_tags=["identify_isotopes"]),
        mcq("M13L2_M4", "A radioisotope is...", ["an unstable isotope that can decay", "an isotope with no nucleus", "an electron-only atom", "a background detector reading"], 0, "Radioisotopes are unstable nuclei.", ["radioactivity_outer_shell_confusion"], skill_tags=["radioisotope"]),
        short("M13L2_M5", "Why can one isotope be stable while another is radioactive?", ["Because different neutron balances can make one nucleus stable and another unstable.", "Because the same proton count can pair with different neutron numbers and therefore different stability."], "Use neutron balance and stability language.", ["radioactivity_outer_shell_confusion", "isotope_element_confusion"], skill_tags=["radioisotope"], acceptance_rules=acceptance_groups(["neutron", "stone"], ["stable", "unstable", "radioactive", "restless"], ["same proton", "same element", "same badge"])),
        mcq("M13L2_M6", "If proton number changes from 6 to 7, the nucleus has become...", ["a different element", "a different isotope of the same element", "a gamma ray only", "a background reading"], 0, "Changing proton number changes the element.", ["proton_identity_confusion", "isotope_element_confusion"], skill_tags=["atomic_number"]),
        short("M13L2_M7", "A learner says, 'same mass number means same element.' What should you say?", ["Same element is decided by the proton number, not just by the mass number.", "Mass number alone does not fix the element; the atomic number does."], "Correct with proton-number identity.", ["isotope_element_confusion", "proton_identity_confusion"], skill_tags=["atomic_number"], acceptance_rules=acceptance_groups(["proton", "atomic number", "badge"], ["element", "identity"], ["not", "rather than"], ["mass number", "A"])),
        mcq("M13L2_M8", "Best summary of Lesson 2:", ["isotopes keep the same proton number but can have different neutron numbers and stability", "isotopes are different elements with the same electrons", "stability depends only on the orbit ring", "all isotopes are radioactive"], 0, "That is the correct isotope story.", ["isotope_element_confusion", "radioactivity_outer_shell_confusion"], skill_tags=["identify_isotopes"]),
    ]
    return lesson_spec(
        "M13_L2",
        "Same-Badge Vaults",
        sim("m13_same_badge_lab", "Same-Badge lab", "Compare isotopes as same-badge vaults with different stone counts and different stability.", ["Build several same-badge vaults.", "Change stone count while badge count stays fixed.", "Sort stable and restless vaults."], ["Explain isotopes correctly.", "Calculate neutron number from A and Z.", "Explain how isotope and stability ideas connect."], ["proton_count", "neutron_count", "stability_mode", "isotope_sort"], "Isotope comparison reasoning."),
        d,
        "Two vault-houses with the same badge count are the same element even if they carry different Balance Stones. Those same-badge different-stone vaults are isotopes, and some are stable while others are restless.",
        "Keep the identity rule visible: badge count first, stone count second, stability third.",
        [prompt_block("What must stay the same if two vaults are isotopes of one element?", "The badge count."), prompt_block("What can change between isotopes?", "The stone count and therefore the mass and stability.")],
        [prompt_block("Hold proton number fixed and change neutron number.", "The element stays the same, but the isotope changes."), prompt_block("Now compare a stable and a restless same-badge vault.", "The stability changes even though the element identity does not.")],
        ["Why are two same-badge vaults still the same element?", "Why can one isotope be stable while another is radioactive?"],
        "Use same-badge language so isotope questions do not accidentally turn into element-identity questions.",
        c,
        t,
        contract(
            concept_targets=["Define isotopes as atoms with the same proton number but different neutron numbers.", "Calculate neutron number from mass number and atomic number.", "Explain why some isotopes are stable while others are radioactive."],
            core_concepts=["Isotopes keep the same proton number and therefore the same element identity.", "Different neutron numbers give different mass numbers.", "A radioisotope is an unstable isotope.", "Changing neutrons can change stability without changing the element."],
            prerequisite_lessons=["M13_L1"],
            misconception_focus=["isotope_element_confusion", "proton_identity_confusion", "radioactivity_outer_shell_confusion"],
            formulas=[relation("N = A - Z", "Neutron number equals mass number minus atomic number.", ["count"], "Use when A and Z are known."), relation("same Z, different N -> isotopes", "The isotope rule keeps atomic number fixed while neutron number changes.", ["comparison"], "Use when classifying nuclei.")],
            representations=[representation("words", "Defines isotopes with proton and neutron language."), representation("diagram", "Shows same-badge vaults side by side."), representation("table", "Compares atomic number, mass number, and neutron number."), representation("formula", "Uses A, Z, and N to classify nuclei.")],
            analogy_map=core_vault_map("the class is sorting same-badge vaults into stable and restless groups"),
            worked_examples=[worked("Carbon-12 and carbon-14 both have proton number 6. Why are they still both carbon?", ["Read the proton number first.", "Notice that both nuclei keep Z = 6.", "State the element-identity rule."], "They are both carbon because proton number 6 fixes the element carbon.", "Element identity follows proton number, not neutron number.", "This is the central isotope rule."), worked("A nucleus has A = 23 and Z = 11. How many neutrons does it have?", ["Use N = A - Z.", "Subtract 11 from 23.", "State the neutron count."], "12 neutrons", "Mass number counts protons plus neutrons, so subtract protons to find neutrons.", "This turns isotope notation into a direct calculation."), worked("Why can two isotopes of the same element have different stability?", ["Keep proton number fixed so the element stays the same.", "Compare the neutron balance in the nuclei.", "State the stability consequence."], "Different neutron balance can make one isotope stable and another unstable.", "Stability depends on nuclear balance, not on outer electrons.", "This prepares the class for radioactivity.")],
            visual_assets=[visual("m13-l2-same-badge-vaults", "same_badge_vaults", "Same-Badge Vaults", "Shows two nuclei with the same badge count but different stone counts and stability.", "The same-element idea and the different-stability idea must stay separate.")],
            animation_assets=[animation("m13-l2-isotope-sort", "same_badge_vaults", "Isotope sort", "Shows same-badge vaults being sorted by neutron count and stability.")],
            simulation_contract=sim_contract("m13-l2-same-badge-lab", "same_badge_vaults", "How do same-badge vaults stay the same element while still becoming different isotopes?", "Start with one badge count and compare two different stone counts.", ["Hold badge count fixed and vary the stone count.", "Sort several nuclei into isotope families.", "Compare stable and restless cases with the same badge count."], "Do not let neutron changes masquerade as a change of element identity.", "Isotopes keep the same proton count while neutron count and stability can change.", [("proton_count", "Badge count", "Keeps the element identity visible."), ("neutron_count", "Stone count", "Creates isotope differences."), ("stability_mode", "Stable or restless mode", "Shows that isotopes can differ in stability.")], [("Element family", "Shows which nuclei belong to the same element."), ("Mass number", "Tracks the total nucleon count."), ("Stability state", "Shows stable versus radioactive cases.")]),
            reflection_prompts=["Why are two same-badge vaults still the same element even if their stone counts differ?", "Why can one isotope be stable while another is restless?"],
            mastery_skills=["identify_isotopes", "atomic_number", "neutron_count", "radioisotope", "proton_identity"],
            variation_plan={"diagnostic": "Fresh attempts rotate between isotope definition, neutron counting, and same-element classification stems.", "concept_gate": "Concept checks vary between same-badge explanations and stability reasoning.", "mastery": "Mastery mixes isotope notation, radioisotope meaning, and explanation prompts before repeating any stem."},
            scaffold_support=scaffold("Isotopes are same-badge vaults with different stone counts.", "Ask which number fixes the element before you ask about mass or stability.", "If two nuclei have the same proton number, must they be the same element?", "Do not let neutron change language turn into element-change language.", "The Core-Vault model keeps same-badge vaults in one family even when their stone balance changes.", "Which quantity should you inspect first when deciding whether two nuclei are isotopes?", [extra_section("Stable versus restless", "Some same-badge vaults are stable while others are radioactive because neutron balance affects nuclear stability.", "Why can stability change without the element changing?"), extra_section("A, Z, and N", "Use Z for proton count, A for total nucleon count, and N = A - Z for neutron count.", "Which notation letter tells you the element directly?")]),
            visual_clarity_checks=visual_checks("same-badge vault"),
        ),
    )


def escape_lesson() -> Dict[str, Any]:
    d = [
        mcq("M13L3_D1", "A Chunk Burst stands for...", ["alpha radiation", "beta radiation", "gamma radiation", "background count"], 0, "Alpha is the 2-proton, 2-neutron chunk.", ["alpha_beta_gamma_mixup"], skill_tags=["identify_radiation"]),
        mcq("M13L3_D2", "A Switch Spark stands for...", ["beta radiation", "alpha radiation", "gamma radiation", "an isotope"], 0, "Beta minus is the fast electron emission in this model.", ["alpha_beta_gamma_mixup"], skill_tags=["identify_radiation"]),
        mcq("M13L3_D3", "A Glow Flash stands for...", ["gamma radiation", "alpha radiation", "beta radiation", "a neutron"], 0, "Gamma is energy only.", ["alpha_beta_gamma_mixup"], skill_tags=["identify_radiation"]),
        mcq("M13L3_D4", "Which escape signal is a heavy cluster of 2 protons and 2 neutrons?", ["alpha", "beta", "gamma", "background"], 0, "That is the alpha particle.", ["alpha_beta_gamma_mixup"], skill_tags=["alpha_change"]),
        mcq("M13L3_D5", "Which radiation is the least penetrating?", ["alpha", "beta", "gamma", "all the same"], 0, "Alpha is stopped most easily.", ["radiation_penetration_order_confusion"], skill_tags=["shielding_order"]),
        mcq("M13L3_D6", "Which material is enough to stop alpha in the school model?", ["paper", "thick lead only", "concrete only", "nothing can stop it"], 0, "Alpha is easily stopped.", ["radiation_penetration_order_confusion"], skill_tags=["shielding_order"]),
        mcq("M13L3_D7", "Which radiation is pure energy and changes only the nucleus's energy state?", ["gamma", "alpha", "beta", "all of them"], 0, "Gamma changes neither proton count nor mass number.", ["gamma_changes_numbers_confusion"], skill_tags=["gamma_change"]),
        short("M13L3_D8", "Why does a Glow Flash leave badge count and total core-piece count unchanged?", ["Because gamma emission releases energy only and does not remove a particle from the nucleus.", "Because a gamma ray changes the nucleus's energy state without changing proton number or mass number."], "Use energy-only language.", ["gamma_changes_numbers_confusion"], skill_tags=["gamma_change"], acceptance_rules=acceptance_groups(["energy", "gamma", "glow flash"], ["no particle", "does not remove a particle", "energy only"], ["unchanged", "same"], ["proton", "badge", "mass number", "total count"])),
    ]
    c = [
        short("M13L3_C1", "How would you compare alpha, beta, and gamma in one sentence?", ["Alpha is a heavy particle, beta is an emitted electron in this model, and gamma is energy only.", "Alpha, beta, and gamma differ in what leaves the nucleus and how penetrating they are."], "Compare what leaves the nucleus.", ["alpha_beta_gamma_mixup"], skill_tags=["identify_radiation"], acceptance_rules=acceptance_groups(["alpha", "beta", "gamma"], ["particle", "electron", "energy"], ["different", "compare", "what leaves"])),
        mcq("M13L3_C2", "In the school beta-minus picture, one neutron changes into...", ["a proton and an emitted electron", "two neutrons", "an alpha particle", "a gamma ray only"], 0, "That is the school beta-minus story.", ["beta_mass_number_confusion"], skill_tags=["beta_change"]),
        mcq("M13L3_C3", "After alpha decay, the daughter nucleus has...", ["2 fewer protons and 4 fewer total nucleons", "1 more proton and the same mass number", "the same proton number and mass number", "4 more protons"], 0, "Alpha removes 2 protons and 2 neutrons.", ["alpha_beta_gamma_mixup"], skill_tags=["alpha_change"]),
        short("M13L3_C4", "Why is it weak to say gamma 'changes the element'?", ["Because gamma changes only the energy state, while proton number stays the same.", "Because the badge count does not change in gamma emission, so the element stays the same."], "Connect element identity to proton number.", ["gamma_changes_numbers_confusion", "proton_identity_confusion"], skill_tags=["gamma_change"], acceptance_rules=acceptance_groups(["gamma", "glow flash"], ["same proton", "same badge", "no proton change"], ["same element", "does not change the element", "identity stays"])),
        mcq("M13L3_C5", "Which order of penetration is strongest to weakest?", ["gamma, beta, alpha", "alpha, beta, gamma", "beta, alpha, gamma", "alpha, gamma, beta"], 0, "Gamma is most penetrating and alpha is least.", ["radiation_penetration_order_confusion"], skill_tags=["shielding_order"]),
        short("M13L3_C6", "Why is beta more penetrating than alpha but less than gamma?", ["Because beta is lighter and more penetrating than alpha, but gamma is energy radiation that penetrates even more strongly.", "Because alpha is a heavy chunk, beta is a fast electron, and gamma is the most penetrating energy form here."], "Compare all three, not just one pair.", ["radiation_penetration_order_confusion", "alpha_beta_gamma_mixup"], skill_tags=["shielding_order"], acceptance_rules=acceptance_groups(["beta"], ["more", "than alpha"], ["less", "than gamma"], ["particle", "electron", "energy", "penetrating"])) ,
    ]
    t = [
        mcq("M13L3_M1", "A nucleus emits alpha radiation. What happens to atomic number Z?", ["it falls by 2", "it rises by 1", "it stays the same", "it falls by 4"], 0, "Alpha removes 2 protons.", ["alpha_beta_gamma_mixup"], skill_tags=["alpha_change"]),
        mcq("M13L3_M2", "A nucleus emits beta-minus radiation. What happens to mass number A?", ["it stays the same", "it falls by 4", "it rises by 1", "it becomes zero"], 0, "Beta minus changes neutron to proton but keeps nucleon total unchanged.", ["beta_mass_number_confusion"], skill_tags=["beta_change"]),
        short("M13L3_M3", "Which shield would you choose first for alpha, beta, and gamma respectively?", ["paper for alpha, thin metal or plastic for beta, and dense lead or concrete for gamma.", "Alpha needs paper, beta needs light shielding such as foil or plastic, and gamma needs dense shielding such as lead."], "Give the shielding in the correct order.", ["radiation_penetration_order_confusion"], skill_tags=["shielding_order"], acceptance_rules=acceptance_groups(["paper", "alpha"], ["foil", "plastic", "beta"], ["lead", "concrete", "gamma"])),
        mcq("M13L3_M4", "Which radiation can be dangerous inside the body even though it is easily stopped outside?", ["alpha", "background only", "gamma only", "none of them"], 0, "Alpha is weakly penetrating but dangerous if taken inside the body.", ["radiation_penetration_order_confusion"], skill_tags=["shielding_order"]),
        short("M13L3_M5", "Why does beta-minus increase atomic number by 1 but keep mass number the same?", ["Because a neutron changes into a proton and an electron is emitted, so the nucleon total stays the same while proton count rises by 1.", "Because beta-minus changes one neutron into one proton, which changes Z but not A."], "Keep proton count and nucleon total separate.", ["beta_mass_number_confusion"], skill_tags=["beta_change"], acceptance_rules=acceptance_groups(["neutron"], ["proton"], ["same", "mass number", "A"], ["rise", "increase"], ["atomic number", "Z"])),
        mcq("M13L3_M6", "Which statement is strongest?", ["Gamma changes energy state but not proton or mass number.", "Gamma is a heavy particle.", "Gamma always changes the element.", "Gamma is stopped by paper."], 0, "Gamma is energy only.", ["gamma_changes_numbers_confusion"], skill_tags=["gamma_change"]),
        short("M13L3_M7", "A learner says, 'all radiation is basically the same thing with different names.' What is the correction?", ["Alpha, beta, and gamma are different because different things leave the nucleus and they have different penetrating power.", "They differ in what leaves the nucleus and in how easily they are absorbed."], "Use both what-leaves and penetration language.", ["alpha_beta_gamma_mixup", "radiation_penetration_order_confusion"], skill_tags=["identify_radiation"], acceptance_rules=acceptance_groups(["alpha", "beta", "gamma"], ["different"], ["leave the nucleus", "particle", "energy"], ["penetration", "shielding"])),
        mcq("M13L3_M8", "Best summary of Lesson 3:", ["alpha, beta, and gamma are distinct escape signals with different nuclear effects and shielding needs", "all radiation changes proton number in the same way", "gamma is the least penetrating and alpha the most", "shielding never matters"], 0, "That keeps both nuclear change and shielding visible.", ["alpha_beta_gamma_mixup", "radiation_penetration_order_confusion"], skill_tags=["identify_radiation"]),
    ]
    return lesson_spec(
        "M13_L3",
        "Escape Signals",
        sim("m13_escape_signal_lab", "Escape signal lab", "Compare alpha, beta, and gamma as three distinct escape signals from restless vaults.", ["Trigger alpha, beta, and gamma cases.", "Compare which count changes each case causes.", "Match the right shielding to each signal."], ["Distinguish alpha, beta, and gamma.", "Explain how counts change in each case.", "Compare penetration and shielding."], ["signal_type", "shield_choice", "count_change", "penetration_compare"], "Radiation-type and shielding reasoning."),
        d,
        "A restless vault can settle by throwing out a Chunk Burst, a Switch Spark, or a Glow Flash. Those escape signals are different in what leaves the nucleus, how the counts change, and how strongly the radiation penetrates.",
        "Read the escape signal first, then decide what leaves, what changes in the counts, and how strongly it penetrates.",
        [prompt_block("Which escape signal is a heavy 2-proton, 2-neutron chunk?", "Chunk Burst, which is alpha."), prompt_block("Which one is energy only?", "Glow Flash, which is gamma.")],
        [prompt_block("Compare alpha, beta, and gamma side by side.", "Keep what leaves the nucleus separate from how easily it penetrates."), prompt_block("Match paper, foil, and lead to the correct signal.", "The shielding order matters because the penetration order differs.")],
        ["Why does a Chunk Burst change both badge count and total core-piece count?", "Why does a Glow Flash leave the counts unchanged?"],
        "Use the escape-signal story to keep the three radiation types distinct instead of turning them into three labels for the same thing.",
        c,
        t,
        contract(
            concept_targets=["Distinguish alpha, beta, and gamma radiation by what leaves the nucleus.", "Compare the count changes caused by each radiation type.", "Compare relative penetration and shielding requirements."],
            core_concepts=["Alpha is a helium-like nucleus with 2 protons and 2 neutrons.", "Beta-minus emission raises proton number by 1 while keeping mass number the same.", "Gamma emission releases energy without changing proton number or mass number.", "Alpha, beta, and gamma differ strongly in penetration and shielding."],
            prerequisite_lessons=["M13_L2"],
            misconception_focus=["alpha_beta_gamma_mixup", "gamma_changes_numbers_confusion", "beta_mass_number_confusion", "radiation_penetration_order_confusion"],
            formulas=[relation("alpha: Z -> Z - 2 and A -> A - 4", "Alpha emission removes 2 protons and 2 neutrons.", ["change rule"], "Use when tracking count changes after alpha decay."), relation("beta-minus: Z -> Z + 1 and A unchanged", "Beta-minus changes a neutron into a proton and emits an electron.", ["change rule"], "Use in school beta-minus questions."), relation("gamma: Z unchanged and A unchanged", "Gamma emission changes the energy state only.", ["change rule"], "Use when no nucleons leave the nucleus.")],
            representations=[representation("words", "Describes what leaves the nucleus in each radiation type."), representation("diagram", "Compares the three escape signals visually."), representation("table", "Matches radiation type to count change, penetration, and shielding."), representation("formula", "Summarizes the Z and A changes for alpha, beta, and gamma.")],
            analogy_map=core_vault_map("the class is comparing three escape signals from a restless vault"),
            worked_examples=[worked("A nucleus emits alpha radiation. What happens to Z and A?", ["Remember that alpha is 2 protons plus 2 neutrons.", "Subtract 2 from proton number.", "Subtract 4 from mass number."], "Z falls by 2 and A falls by 4", "Alpha removes a 2-proton, 2-neutron chunk from the nucleus.", "This is the cleanest first count-change pattern."), worked("A nucleus emits beta-minus radiation. What changes?", ["Use the school story: one neutron becomes one proton and an electron is emitted.", "Increase proton number by 1.", "Keep mass number unchanged."], "Z rises by 1 and A stays the same", "Beta-minus changes the badge count by converting one neutron into one proton without changing the total nucleon count.", "This distinguishes beta from alpha clearly."), worked("Why does gamma emission not change the element?", ["Ask whether any proton leaves the nucleus.", "Notice that gamma is energy only.", "Apply the identity rule."], "The element stays the same because proton number does not change.", "Element identity follows proton number, and gamma leaves that unchanged.", "This blocks a very common gamma misconception.")],
            visual_assets=[visual("m13-l3-escape-signals", "escape_signals", "Escape Signals", "Shows alpha, beta, and gamma side by side with their shielding and penetration differences.", "The three signals and the shielding order must stay visually distinct.")],
            animation_assets=[animation("m13-l3-signal-release", "escape_signals", "Signal release", "Shows a restless vault settling by alpha, beta, or gamma emission.")],
            simulation_contract=sim_contract("m13-l3-escape-signal-lab", "escape_signals", "How do alpha, beta, and gamma differ in what leaves the vault and in how they are shielded?", "Start with one restless vault and trigger each of the three escape signals one at a time.", ["Compare the change in badge and stone counts for alpha, beta, and gamma.", "Match paper, foil, and dense shielding to the correct signal.", "Compare the relative penetration order."], "Do not collapse alpha, beta, and gamma into three names for the same process.", "Different escape signals remove different things from the nucleus and therefore change counts and shielding needs differently.", [("signal_type", "Escape signal", "Chooses alpha, beta, or gamma."), ("shield_choice", "Shield choice", "Lets the learner compare penetration with shielding."), ("count_change", "Count-change panel", "Keeps Z and A changes visible.")], [("Radiation identity", "Names the current signal clearly."), ("Count change", "Shows what changes in Z and A."), ("Shield result", "Shows whether the chosen shield works.")]),
            reflection_prompts=["Why does a Chunk Burst change both badge count and total core-piece count?", "Why does a Glow Flash leave the counts unchanged?"],
            mastery_skills=["identify_radiation", "alpha_change", "beta_change", "gamma_change", "shielding_order"],
            variation_plan={"diagnostic": "Fresh attempts rotate between identification, shielding, and count-change stems.", "concept_gate": "Concept checks vary between gamma-not-counts and beta-versus-alpha reasoning.", "mastery": "Mastery mixes shielding, notation-change, and explanation prompts before repeating any stem."},
            scaffold_support=scaffold("A restless vault can settle by alpha, beta, or gamma, and those are different escape signals, not different words for the same thing.", "Name the signal first, then ask what leaves the nucleus and what that does to Z and A.", "If the escape signal is gamma, should the proton number change?", "Do not let the three radiation types blur into one generic idea of radiation.", "Chunk Burst, Switch Spark, and Glow Flash are different because different things leave the vault and different shields stop them.", "Which two checks should you make after naming the signal: what leaves, or what color the diagram is?", [extra_section("Penetration order", "Alpha is the least penetrating, beta is in the middle, and gamma is the most penetrating in the school model.", "Which of the three needs the densest shielding?"), extra_section("Count change order", "Alpha changes both Z and A, beta changes Z only, and gamma changes neither count.", "Which signal leaves A unchanged but raises Z by 1?")]),
            visual_clarity_checks=visual_checks("escape-signal"),
        ),
    )


def half_life_lesson() -> Dict[str, Any]:
    d = [
        mcq("M13L4_D1", "Settle Span stands for...", ["half-life", "background radiation", "atomic number", "gamma shielding"], 0, "Settle Span is the half-life in the model.", ["half_life_fixed_timer_confusion"], skill_tags=["define_half_life"]),
        mcq("M13L4_D2", "Half-life is best defined as the time for...", ["half a large group of identical unstable nuclei to decay", "every nucleus to wait before decaying", "a detector to reach zero", "one isotope to become stable forever"], 0, "Half-life is a population rule.", ["half_life_fixed_timer_confusion"], skill_tags=["define_half_life"]),
        mcq("M13L4_D3", "A single unstable nucleus decays...", ["randomly", "exactly after one half-life", "only when background is zero", "only if electrons leave first"], 0, "Single nuclei decay unpredictably.", ["half_life_fixed_timer_confusion"], skill_tags=["random_decay"]),
        mcq("M13L4_D4", "After two half-lives, the fraction of the original sample remaining undecayed is...", ["1/4", "1/2", "1/3", "3/4"], 0, "Half, then half again.", ["half_life_linear_drop_confusion"], skill_tags=["half_life_fraction"]),
        mcq("M13L4_D5", "A sample drops from 80 to 40 to 20 over equal time intervals. This shows...", ["repeated halving", "a linear drop by a fixed number", "that every nucleus has the same timer", "zero background"], 0, "Half-life follows halving, not fixed subtraction.", ["half_life_linear_drop_confusion"], skill_tags=["half_life_fraction"]),
        mcq("M13L4_D6", "After three half-lives, 64 restless vaults become...", ["8", "16", "32", "4"], 0, "64 -> 32 -> 16 -> 8.", ["half_life_linear_drop_confusion"], skill_tags=["half_life_number"]),
        short("M13L4_D7", "Why can a class predict the half-life pattern for a crowd but not for one single vault?", ["Because single nuclei decay randomly, but a large group follows a predictable statistical halving pattern.", "Because half-life is a population rule even though individual decay is random."], "Use random-single and predictable-group language.", ["half_life_fixed_timer_confusion"], skill_tags=["random_decay"], acceptance_rules=acceptance_groups(["single", "individual"], ["random"], ["group", "crowd", "population"], ["predictable", "statistical", "halving"])),
        short("M13L4_D8", "Why is subtracting the same number each time weaker than halving in a half-life lesson?", ["Because half-life means the sample falls by the same fraction each interval, not by the same fixed number.", "Because radioactive decay is exponential halving rather than a straight-line drop by equal amounts."], "Use fraction-not-fixed-number language.", ["half_life_linear_drop_confusion"], skill_tags=["half_life_fraction"], acceptance_rules=acceptance_groups(["half-life", "halving", "fraction"], ["not", "rather than"], ["same number", "fixed number", "linear"])),
    ]
    c = [
        short("M13L4_C1", "How would you explain half-life without using the word formula?", ["It is the equal time interval over which half of a large group of identical unstable nuclei decay.", "It is the crowd-halving time for a radioactive sample."], "Use equal-interval and half-group language.", ["half_life_fixed_timer_confusion"], skill_tags=["define_half_life"], acceptance_rules=acceptance_groups(["half", "crowd", "group", "sample"], ["equal time", "time interval", "same interval"], ["unstable", "radioactive"])),
        mcq("M13L4_C2", "If 200 nuclei remain undecayed at the start, how many remain after one half-life?", ["100", "50", "150", "200"], 0, "Half remain after one half-life.", ["half_life_linear_drop_confusion"], skill_tags=["half_life_number"]),
        mcq("M13L4_C3", "If 25% of the sample remains, how many half-lives have passed?", ["2", "1", "3", "4"], 0, "100% -> 50% -> 25%.", ["half_life_linear_drop_confusion"], skill_tags=["half_life_fraction"]),
        short("M13L4_C4", "Why is it weak to say 'every nucleus waits its turn for the same amount of time'?", ["Because each nucleus decays randomly, so half-life belongs to the group pattern rather than to each individual nucleus.", "Because half-life is not a personal countdown built into each nucleus."], "Keep the randomness at the single-nucleus level.", ["half_life_fixed_timer_confusion"], skill_tags=["random_decay"], acceptance_rules=acceptance_groups(["single", "individual"], ["random"], ["group", "population", "crowd"], ["not", "rather than"], ["same time", "countdown", "timer"])),
        mcq("M13L4_C5", "Which graph shape best matches radioactive decay?", ["a curve that halves over equal intervals", "a straight line down by equal amounts", "a flat line", "a line that rises upward"], 0, "Decay is exponential, not linear.", ["half_life_linear_drop_confusion"], skill_tags=["half_life_fraction"]),
        short("M13L4_C6", "What does one Settle Span do to the undecayed crowd?", ["It leaves half of the original undecayed group still not decayed.", "It cuts the undecayed crowd to half its previous size after one equal time interval."], "Use half-the-remaining-group language.", ["half_life_fixed_timer_confusion"], skill_tags=["define_half_life"], acceptance_rules=acceptance_groups(["half"], ["undecayed", "remaining", "crowd", "group"], ["time interval", "span"])),
    ]
    t = [
        mcq("M13L4_M1", "A sample has a half-life of 5 hours. Starting from 160 nuclei, how many remain after 10 hours?", ["40", "80", "20", "120"], 0, "Two half-lives pass in 10 hours.", ["half_life_linear_drop_confusion"], skill_tags=["half_life_number"]),
        short("M13L4_M2", "A sample falls from 120 to 30 over two half-lives. Explain the halving path.", ["120 goes to 60 after one half-life and 60 goes to 30 after the second half-life.", "It halves twice: first to 60, then to 30."], "Track each halving step.", ["half_life_linear_drop_confusion"], skill_tags=["half_life_number"], acceptance_rules=acceptance_groups(["120"], ["60"], ["30"], ["half", "halve"])),
        mcq("M13L4_M3", "If a sample has 1/8 of its original nuclei left, how many half-lives have passed?", ["3", "2", "4", "8"], 0, "1 -> 1/2 -> 1/4 -> 1/8.", ["half_life_linear_drop_confusion"], skill_tags=["half_life_fraction"]),
        mcq("M13L4_M4", "What stays the same in successive half-lives?", ["the time interval, not the number lost", "the number lost, not the time", "the background count only", "the proton number of the whole sample"], 0, "Half-life keeps equal intervals, not equal subtraction.", ["half_life_linear_drop_confusion"], skill_tags=["define_half_life"]),
        short("M13L4_M5", "Why can two identical samples with the same half-life still lose different individual nuclei first?", ["Because the half-life is a statistical rule for the group, while each nucleus decays randomly.", "Because the same half-life does not tell you which individual nucleus goes first."], "Use statistical-group language.", ["half_life_fixed_timer_confusion"], skill_tags=["random_decay"], acceptance_rules=acceptance_groups(["half-life"], ["group", "population", "statistical"], ["individual", "single"], ["random"])),
        mcq("M13L4_M6", "A graph shows 400 -> 200 -> 100 -> 50 at equal time steps. Which statement is strongest?", ["The sample has a constant half-life over those intervals.", "The sample loses 200 each step.", "Each nucleus waits exactly three steps.", "The background is zero."], 0, "That is a halving pattern.", ["half_life_linear_drop_confusion", "half_life_fixed_timer_confusion"], skill_tags=["define_half_life"]),
        short("M13L4_M7", "A learner says, 'after one half-life the sample is gone because half died already.' What is the correction?", ["After one half-life, half the sample remains undecayed; it is not gone.", "One half-life leaves half the nuclei still undecayed, not zero."], "Correct with half-remains language.", ["half_life_linear_drop_confusion"], skill_tags=["define_half_life"], acceptance_rules=acceptance_groups(["half"], ["remain", "remaining", "undecayed"], ["not gone", "not zero"])),
        mcq("M13L4_M8", "Best summary of Lesson 4:", ["half-life is a predictable halving pattern for a large group even though single decays are random", "half-life is a personal timer inside each nucleus", "radioactivity drops by equal numbers each interval", "background radiation decides half-life"], 0, "That is the correct population-versus-individual summary.", ["half_life_fixed_timer_confusion", "half_life_linear_drop_confusion"], skill_tags=["random_decay"]),
    ]
    return lesson_spec(
        "M13_L4",
        "Settle Span Arena",
        sim("m13_settle_span_lab", "Settle Span lab", "Explore half-life as a crowd-halving pattern for unstable vaults.", ["Start with a large crowd.", "Run several equal time intervals.", "Compare one-nucleus randomness with crowd behavior."], ["Define half-life clearly.", "Predict remaining sample size after several half-lives.", "Explain why half-life is statistical."], ["initial_count", "half_life_steps", "time_elapsed", "remaining_count"], "Half-life and statistical decay reasoning."),
        d,
        "Settle Span is not a personal timer hiding inside each restless vault. It is the equal interval over which half of a large crowd of identical restless vaults decay, so the group shows a clean halving pattern even though single decays are random.",
        "When you see half-life, decide whether the question is about one nucleus or the whole crowd.",
        [prompt_block("What fraction remains after one Settle Span?", "One half."), prompt_block("Does one nucleus obey a visible countdown clock?", "No, single decay is random.")],
        [prompt_block("Start with a crowd and let one half-life pass.", "Half of the crowd remains undecayed."), prompt_block("Now let another equal interval pass.", "The remaining group halves again.")],
        ["Why can the class predict the half-life pattern for a crowd even though it cannot predict one single vault?", "Why is halving stronger than subtracting the same number each time?"],
        "Use the arena model to keep the group-halving rule separate from single-nucleus randomness.",
        c,
        t,
        contract(
            concept_targets=["Define half-life as the time for half a large radioactive sample to decay.", "Predict remaining fraction or number after repeated half-lives.", "Explain why half-life is statistical rather than a personal timer."],
            core_concepts=["Single unstable nuclei decay randomly.", "Large groups show a predictable halving pattern.", "Equal half-life intervals halve the remaining sample.", "Radioactive decay is not a straight-line drop by equal numbers."],
            prerequisite_lessons=["M13_L2", "M13_L3"],
            misconception_focus=["half_life_fixed_timer_confusion", "half_life_linear_drop_confusion"],
            formulas=[relation("remaining = initial x (1/2)^n", "After n half-lives, the undecayed sample is the initial amount multiplied by (1/2)^n.", ["count", "fraction"], "Use when the number of half-lives is known."), relation("number of half-lives = elapsed time / half-life", "Count how many equal halving intervals fit into the elapsed time.", ["interval count"], "Use in simple half-life calculations.")],
            representations=[representation("words", "Explains half-life as a crowd rule rather than a personal timer."), representation("diagram", "Shows repeated halving of a large group."), representation("graph", "Shows the curved decay pattern."), representation("formula", "Calculates remaining sample after repeated halvings.")],
            analogy_map=core_vault_map("the class is watching a crowd of restless vaults thin out by halves"),
            worked_examples=[worked("A sample starts with 80 nuclei. How many remain after two half-lives?", ["Half 80 to get 40 after one half-life.", "Half 40 to get 20 after the second half-life.", "State the remaining count."], "20 nuclei", "Each equal half-life interval halves the remaining sample.", "This is the first concrete half-life calculation."), worked("A sample has half-life 5 hours. Starting from 160 nuclei, how many remain after 10 hours?", ["Work out how many half-lives fit into 10 hours.", "Two half-lives pass.", "Halve twice: 160 -> 80 -> 40."], "40 nuclei", "Ten hours is two half-life intervals, so the sample halves twice.", "This connects time with the halving count."), worked("Why is 'every nucleus waits 5 hours' a weak statement for a 5-hour half-life?", ["Ask whether half-life refers to one nucleus or a large group.", "Remember that single nuclei decay randomly.", "State the group rule."], "Because half-life describes the sample-halving pattern for a large group, not the exact decay time of one nucleus.", "Half-life is statistical, not personal.", "This blocks the most common half-life misconception directly.")],
            visual_assets=[visual("m13-l4-half-life-crowd", "settle_span", "Settle Span Arena", "Shows a crowd halving over equal intervals rather than losing the same number each time.", "The equal-interval and half-remaining labels must stay easy to compare.")],
            animation_assets=[animation("m13-l4-crowd-halving", "settle_span", "Crowd halving", "Shows a large crowd of restless vaults thinning by halves over equal intervals.")],
            simulation_contract=sim_contract("m13-l4-settle-span-lab", "settle_span", "How does a crowd of restless vaults show a predictable half-life pattern even though single decays are random?", "Start with a large crowd and run one equal interval before predicting the next one.", ["Run repeated equal intervals and compare remaining fractions.", "Compare one-vault randomness with group-level halving.", "Switch between number and fraction descriptions of what remains."], "Do not treat half-life as if every nucleus carries the same personal countdown clock.", "Half-life is a statistical crowd rule that halves the remaining sample over equal intervals.", [("initial_count", "Starting crowd", "Shows how many unstable vaults are in the sample."), ("half_life_steps", "Number of settle spans", "Shows how many equal intervals have passed."), ("time_elapsed", "Elapsed time", "Links real time to half-life count.")], [("Remaining count", "Shows how many unstable vaults remain."), ("Remaining fraction", "Shows the sample as a fraction of the original."), ("Decay pattern", "Confirms that the pattern is halving rather than fixed subtraction.")]),
            reflection_prompts=["Why can the class predict the half-life pattern for a crowd even though it cannot predict one single vault?", "Why is subtracting the same number each time weaker than halving in radioactive decay?"],
            mastery_skills=["define_half_life", "random_decay", "half_life_fraction", "half_life_number", "elapsed_half_lives"],
            variation_plan={"diagnostic": "Fresh attempts rotate between definition, fraction, and population-versus-individual stems.", "concept_gate": "Concept checks vary between half-remains reasoning and random-single-nucleus explanations.", "mastery": "Mastery mixes number, fraction, and explanation questions before repeating any stem."},
            scaffold_support=scaffold("Settle Span is a crowd-halving rule, not a personal timer for each nucleus.", "Ask first whether the question is about the whole sample or one nucleus. Then count equal halving intervals.", "After two settle spans, what fraction remains?", "Do not imagine every nucleus carrying the same alarm clock.", "The arena model works because crowd behavior becomes predictable even when each single vault still changes at random.", "Which sentence belongs to the crowd, and which sentence wrongly belongs to each single nucleus?", [extra_section("Fraction thinking", "Each half-life halves what is left, so the remaining fraction follows 1, 1/2, 1/4, 1/8, and so on.", "What fraction remains after three half-lives?"), extra_section("Random single nuclei", "You cannot know which nucleus decays next, but you can still predict the group pattern well for a large sample.", "Why is one-nucleus prediction weaker than crowd prediction?")]),
            visual_clarity_checks=visual_checks("settle-span"),
        ),
    )


def background_lesson() -> Dict[str, Any]:
    d = [
        mcq("M13L5_D1", "Ambient Buzz stands for...", ["background radiation", "alpha decay only", "half-life", "mass number"], 0, "Ambient Buzz is the low-level environmental radiation.", ["background_zero_confusion"], skill_tags=["background_sources"]),
        mcq("M13L5_D2", "Why does a detector usually not read zero in an empty room?", ["because background radiation is still present", "because every room has a hidden source", "because gamma changes the detector number", "because half-life is zero"], 0, "Background radiation is normal.", ["background_zero_confusion"], skill_tags=["background_sources"]),
        mcq("M13L5_D3", "Which is a natural source of background radiation?", ["cosmic rays", "only man-made reactors", "only batteries", "none of them"], 0, "Cosmic radiation is part of background.", ["background_zero_confusion"], skill_tags=["background_sources"]),
        mcq("M13L5_D4", "Which location often has a higher background reading?", ["high altitude", "everywhere exactly the same", "inside lead only", "only underwater"], 0, "Background varies with location and conditions.", ["background_zero_confusion"], skill_tags=["background_variation"]),
        mcq("M13L5_D5", "A detector reads 35 counts per minute near a source and 12 counts per minute as background. The source-only count rate is...", ["23 counts per minute", "47 counts per minute", "12 counts per minute", "35 counts per minute"], 0, "Subtract background from the measured rate.", ["background_means_contamination_confusion"], skill_tags=["background_subtraction"]),
        mcq("M13L5_D6", "A non-zero detector reading always means contamination is present.", ["false", "true", "only for alpha", "only for gamma"], 0, "Background radiation already gives some reading.", ["background_means_contamination_confusion"], skill_tags=["background_sources"]),
        short("M13L5_D7", "Why can the detector still click when no special source is placed nearby?", ["Because natural background radiation from the environment is always present.", "Because the detector is picking up normal environmental background radiation."], "Use natural-background language.", ["background_zero_confusion"], skill_tags=["background_sources"], acceptance_rules=acceptance_groups(["background", "ambient buzz"], ["always", "still", "normal"], ["environment", "natural", "cosmic", "rocks", "air"])),
        short("M13L5_D8", "Why is 'any reading means contamination' weak?", ["Because a detector normally reads some background radiation even with no contamination present.", "Because background radiation gives a normal non-zero reading, so you must compare with background first."], "Use compare-with-background language.", ["background_means_contamination_confusion"], skill_tags=["background_subtraction"], acceptance_rules=acceptance_groups(["background"], ["normal", "non-zero", "still"], ["not", "rather than"], ["contamination"])),
    ]
    c = [
        short("M13L5_C1", "How would you explain background radiation in one sentence?", ["Background radiation is the low-level radiation always present from natural and environmental sources.", "It is the normal ambient radiation the detector can pick up even without a special source."], "Use always-present environmental-source language.", ["background_zero_confusion"], skill_tags=["background_sources"], acceptance_rules=acceptance_groups(["background", "ambient"], ["always", "normal", "present"], ["environment", "natural", "sources"])),
        mcq("M13L5_C2", "Which pair belongs to background radiation?", ["cosmic rays and rocks", "only alpha from one sample", "only beta from a battery", "only radiation inside hospitals"], 0, "Cosmic radiation and rocks are classic background sources.", ["background_zero_confusion"], skill_tags=["background_sources"]),
        mcq("M13L5_C3", "Measured count rate = 42 counts per minute, background = 15 counts per minute. Corrected source count rate = ...", ["27 counts per minute", "57 counts per minute", "15 counts per minute", "42 counts per minute"], 0, "Subtract background.", ["background_means_contamination_confusion"], skill_tags=["background_subtraction"]),
        short("M13L5_C4", "Why should background be measured before you talk about a source-only count rate?", ["Because you need to subtract the normal background first to find the source-only reading.", "Because the detector includes background counts as well as source counts."], "Use subtraction-before-conclusion language.", ["background_means_contamination_confusion"], skill_tags=["background_subtraction"], acceptance_rules=acceptance_groups(["subtract", "difference"], ["background"], ["source", "source-only", "corrected"])),
        mcq("M13L5_C5", "Which statement is strongest?", ["Background radiation can vary from place to place and time to time.", "Background radiation is identical everywhere.", "Background radiation is always contamination.", "Background radiation means the detector is broken."], 0, "Background varies with conditions and location.", ["background_zero_confusion"], skill_tags=["background_variation"]),
        short("M13L5_C6", "Why can altitude change the background reading?", ["Because higher altitude usually exposes the detector to more cosmic radiation.", "Because the cosmic-ray part of background radiation can be stronger higher up."], "Use cosmic-ray language.", ["background_zero_confusion"], skill_tags=["background_variation"], acceptance_rules=acceptance_groups(["altitude", "higher"], ["cosmic"], ["more", "greater", "stronger"], ["background"])),
    ]
    t = [
        mcq("M13L5_M1", "A detector reads 18 counts per minute in the room and 51 counts per minute near a sample. The sample-only count rate is...", ["33 counts per minute", "69 counts per minute", "18 counts per minute", "51 counts per minute"], 0, "Corrected count = measured - background.", ["background_means_contamination_confusion"], skill_tags=["background_subtraction"]),
        short("M13L5_M2", "Why is a source count rate stronger evidence than an uncorrected detector reading?", ["Because the source count rate has had the background removed, so it shows the sample's extra effect more clearly.", "Because uncorrected readings include both the source and the normal background."], "Use corrected-reading language.", ["background_means_contamination_confusion"], skill_tags=["background_subtraction"], acceptance_rules=acceptance_groups(["background"], ["removed", "subtract", "corrected"], ["source", "sample"], ["clearer", "extra"])),
        mcq("M13L5_M3", "Which situation could naturally raise background radiation?", ["higher altitude", "changing the proton number of the detector", "turning a gamma ray into alpha", "removing all neutrons from Earth"], 0, "Altitude changes background.", ["background_zero_confusion"], skill_tags=["background_variation"]),
        mcq("M13L5_M4", "Which statement best fits Ambient Buzz?", ["The detector usually sees some background even without a special source.", "The detector must read zero before any measurement.", "Background radiation only exists in laboratories.", "Background radiation changes the element identity of nearby atoms automatically."], 0, "Ambient Buzz is normal.", ["background_zero_confusion"], skill_tags=["background_sources"]),
        short("M13L5_M5", "A learner says, 'the detector clicked, so the room is contaminated.' What correction should you make?", ["A detector can click because of normal background radiation, so you must compare with the background level first.", "A non-zero reading alone does not prove contamination because the environment already gives some background counts."], "Use compare-first language.", ["background_means_contamination_confusion"], skill_tags=["background_subtraction"], acceptance_rules=acceptance_groups(["background"], ["compare", "measure first", "subtract"], ["not", "does not"], ["contamination"])),
        mcq("M13L5_M6", "If measured count rate equals background count rate, the corrected source count rate is...", ["0", "the background value", "double the background", "undefined"], 0, "No extra count above background means zero corrected source count.", ["background_means_contamination_confusion"], skill_tags=["background_subtraction"]),
        short("M13L5_M7", "Why is background radiation called ambient in the model?", ["Because it is around us in the environment even when no special source has been added.", "Because it is the normal environmental radiation in the surroundings."], "Use around-us environmental language.", ["background_zero_confusion"], skill_tags=["background_sources"], acceptance_rules=acceptance_groups(["around", "environment", "surroundings"], ["normal", "ambient", "background"], ["no special source", "even without a source"])),
        mcq("M13L5_M8", "Best summary of Lesson 5:", ["background radiation is a normal environmental presence, so readings must be compared with background before strong conclusions are made", "all non-zero readings mean contamination", "background radiation never changes with place", "detectors should read zero in any safe room"], 0, "That keeps background and contamination separate.", ["background_zero_confusion", "background_means_contamination_confusion"], skill_tags=["background_sources"]),
    ]
    return lesson_spec(
        "M13_L5",
        "Ambient Buzz Detective",
        sim("m13_ambient_buzz_lab", "Ambient Buzz lab", "Compare detector readings, natural background sources, and corrected source counts.", ["Measure background first.", "Measure near a source second.", "Subtract background to find the source-only rate."], ["Explain background radiation correctly.", "Correct detector readings by subtracting background.", "Explain why non-zero readings do not automatically mean contamination."], ["background_level", "source_level", "location_mode", "corrected_rate"], "Background-radiation reasoning."),
        d,
        "Even without a dramatic source in the scene, the arena still carries Ambient Buzz. Cosmic rays, rocks, air, water, food, and even the body can all contribute, so a detector often reports a non-zero background before any special source is added.",
        "Measure the background first, then compare any source reading against it before you draw a conclusion.",
        [prompt_block("Why can a detector read above zero even when the table looks empty?", "Because background radiation is still present."), prompt_block("How do you find source-only count rate?", "Subtract background from the measured count rate.")],
        [prompt_block("Read the background count first.", "This is the baseline you must subtract later."), prompt_block("Now place the source and measure again.", "The extra count above background belongs to the source.")],
        ["Why does the detector still click when no special source is placed nearby?", "Why is 'any reading means contamination' weaker than a corrected-count explanation?"],
        "Use the Ambient Buzz story so background radiation becomes normal context rather than a confusing exception.",
        c,
        t,
        contract(
            concept_targets=["Explain background radiation as a normal environmental presence.", "Name common natural sources of background radiation.", "Calculate corrected source count rate by subtracting background."],
            core_concepts=["Detectors usually register some normal background radiation.", "Background radiation can come from cosmic rays, rocks, air, food, and the body.", "Background levels vary with location and conditions.", "Source-only count rate is found by subtracting background from the measured count rate."],
            prerequisite_lessons=["M13_L3"],
            misconception_focus=["background_zero_confusion", "background_means_contamination_confusion"],
            formulas=[relation("corrected count rate = measured count rate - background count rate", "Subtract the normal background to isolate the source contribution.", ["counts per minute"], "Use in detector-reading questions.")],
            representations=[representation("words", "Explains why background radiation is normal."), representation("diagram", "Shows a detector surrounded by environmental sources."), representation("table", "Separates measured, background, and corrected count rates."), representation("formula", "Uses subtraction to find the source-only rate.")],
            analogy_map=core_vault_map("the class is comparing a detector's normal Ambient Buzz with the extra effect from a source"),
            worked_examples=[worked("A detector reads 42 counts per minute near a source and 15 counts per minute as background. What is the corrected source count rate?", ["Write corrected = measured - background.", "Substitute 42 and 15.", "Subtract to find the extra source contribution."], "27 counts per minute", "The detector reading includes both background and source counts, so background must be removed first.", "This is the key background-subtraction skill."), worked("Why can a detector click even when no source has been placed nearby?", ["List the environmental sources of background radiation.", "Remember that detectors are sensitive to those sources.", "State the normal-reading conclusion."], "Because normal background radiation is still present in the environment.", "A non-zero detector reading is not unusual even before a special source is added.", "This blocks the zero-background expectation."), worked("Why is 'the room is contaminated because the detector clicked' too strong?", ["Ask whether the background was measured.", "Remember that the detector already sees normal background.", "State what extra evidence is needed."], "Because a non-zero reading alone does not prove contamination; it must be compared with the background level.", "Background-first thinking is essential in detector interpretation.", "This supports practical interpretation of count-rate data.")],
            visual_assets=[visual("m13-l5-ambient-buzz", "ambient_buzz", "Ambient Buzz", "Shows a detector surrounded by environmental background sources.", "The detector reading and the source labels must stay easy to connect.")],
            animation_assets=[animation("m13-l5-detector-clicks", "ambient_buzz", "Detector clicks", "Shows the detector continuing to register background counts before and after a source is added.")],
            simulation_contract=sim_contract("m13-l5-ambient-buzz-lab", "ambient_buzz", "Why does a detector still click when no special source has been placed nearby, and how do you isolate a source reading?", "Start by measuring the background in an empty-looking scene before adding any source.", ["Compare two locations with different background levels.", "Add a source and subtract the background to find the source-only count rate.", "Test whether a non-zero reading alone proves contamination."], "Do not treat every detector click as evidence of contamination.", "Background radiation is normal, and careful detector work subtracts background before naming the source contribution.", [("background_level", "Background setting", "Shows the normal environmental count rate."), ("source_level", "Source strength", "Adds the extra count from a placed source."), ("location_mode", "Location mode", "Shows why background can vary with setting or altitude.")], [("Measured count rate", "Shows the total detector reading."), ("Background count rate", "Shows the normal environmental part."), ("Corrected source count rate", "Shows the extra counts due to the source alone.")]),
            reflection_prompts=["Why does the detector still click when no special source is placed nearby?", "Why is 'any reading means contamination' weaker than a corrected-count explanation?"],
            mastery_skills=["background_sources", "background_variation", "background_subtraction", "corrected_count_rate", "detector_interpretation"],
            variation_plan={"diagnostic": "Fresh attempts rotate between source-identification, background-subtraction, and contamination-versus-background stems.", "concept_gate": "Concept checks vary between background definitions and corrected-count reasoning.", "mastery": "Mastery mixes subtraction, source reasoning, and explanation prompts before repeating any stem."},
            scaffold_support=scaffold("Ambient Buzz means a detector can read above zero even with no special source in place.", "Measure the background first, then compare or subtract before naming the source effect.", "If the detector reads 35 counts per minute near a sample and 12 as background, what must you do first?", "Do not let every non-zero reading turn into a contamination claim.", "The detector lives in a noisy environment, so it hears the room before it hears the sample.", "Which reading belongs to the room, and which part is the sample's extra signal?", [extra_section("Natural sources", "Cosmic rays, rocks, radon, food, water, and the body can all contribute to background radiation.", "Which of those sources can exist even in an ordinary room?"), extra_section("Corrected count", "Subtract the background count rate from the measured count rate to isolate the source-only reading.", "Why is subtraction the key step in detector questions?")]),
            visual_clarity_checks=visual_checks("ambient-buzz"),
        ),
    )


def ledger_lesson() -> Dict[str, Any]:
    d = [
        mcq("M13L6_D1", "The Vault Ledger stands for...", ["the decay equation", "the orbit ring", "background radiation only", "a shielding sheet"], 0, "The ledger is the before-and-after decay record.", ["decay_equation_balance_confusion"], skill_tags=["balance_decay_equation"]),
        mcq("M13L6_D2", "In any decay equation, which two totals must balance across the arrow?", ["atomic number and mass number", "electron number and color", "half-life and background", "shielding and time"], 0, "Badge count and total core-piece count must balance.", ["decay_equation_balance_confusion"], skill_tags=["balance_decay_equation"]),
        mcq("M13L6_D3", "After alpha decay, the daughter nucleus has...", ["atomic number 2 less and mass number 4 less", "atomic number 1 more and mass number unchanged", "both numbers unchanged", "mass number 2 less and atomic number 4 less"], 0, "Alpha removes 2 protons and 2 neutrons.", ["alpha_beta_gamma_mixup", "decay_equation_balance_confusion"], skill_tags=["alpha_ledger"]),
        mcq("M13L6_D4", "After beta-minus decay, the daughter nucleus has...", ["atomic number 1 more and mass number unchanged", "atomic number 2 less and mass number 4 less", "both numbers unchanged", "mass number 1 less and atomic number unchanged"], 0, "Beta-minus raises Z by 1 while A stays the same.", ["beta_mass_number_confusion", "decay_equation_balance_confusion"], skill_tags=["beta_ledger"]),
        mcq("M13L6_D5", "After gamma decay, the daughter nucleus has...", ["the same atomic number and the same mass number", "atomic number 1 more", "mass number 4 less", "a different element"], 0, "Gamma changes the energy state only.", ["gamma_changes_numbers_confusion", "decay_equation_balance_confusion"], skill_tags=["gamma_ledger"]),
        mcq("M13L6_D6", "Which count fixes the element identity in the ledger?", ["atomic number Z", "mass number A only", "half-life", "background count"], 0, "Element identity follows proton number.", ["proton_identity_confusion", "decay_equation_balance_confusion"], skill_tags=["atomic_number"]),
        short("M13L6_D7", "Why must a nuclear decay equation balance both badge count and total core-piece count?", ["Because proton number and total nucleon number are conserved across the nuclear change.", "Because the daughter nucleus plus emitted radiation must keep the same total atomic number and mass number as the parent."], "Use conserve-and-balance language.", ["decay_equation_balance_confusion"], skill_tags=["balance_decay_equation"], acceptance_rules=acceptance_groups(["balance", "conserve", "same total"], ["atomic number", "badge", "proton"], ["mass number", "total core-piece", "total nucleon"])),
        short("M13L6_D8", "Why does gamma emission leave the ledger counts unchanged?", ["Because gamma emission releases energy only, so no proton or neutron leaves the nucleus.", "Because gamma changes the energy state without changing atomic number or mass number."], "Use energy-only and unchanged-count language.", ["gamma_changes_numbers_confusion", "decay_equation_balance_confusion"], skill_tags=["gamma_ledger"], acceptance_rules=acceptance_groups(["gamma", "energy", "glow flash"], ["no proton", "no neutron", "no particle"], ["same", "unchanged"], ["atomic number", "mass number", "counts"])) ,
    ]
    c = [
        short("M13L6_C1", "How would you explain the Vault Ledger in one sentence?", ["It is the before-and-after nuclear bookkeeping that keeps atomic number and mass number balanced across the decay.", "It is the decay-equation record that checks whether the nuclear counts still balance after alpha, beta, or gamma emission."], "Use bookkeeping and balancing language.", ["decay_equation_balance_confusion"], skill_tags=["balance_decay_equation"], acceptance_rules=acceptance_groups(["ledger", "bookkeeping", "equation"], ["balance", "conserve"], ["atomic number", "badge"], ["mass number", "total"])) ,
        mcq("M13L6_C2", "Which statement is strongest?", ["Alpha changes both Z and A, beta-minus changes Z only, and gamma changes neither.", "All three radiation types change both counts.", "Gamma changes the element but not the mass number.", "Beta-minus lowers the mass number by 1."], 0, "Keep the three change rules separate.", ["alpha_beta_gamma_mixup", "beta_mass_number_confusion", "gamma_changes_numbers_confusion"], skill_tags=["balance_decay_equation"]),
        mcq("M13L6_C3", "Which daughter numbers fit alpha decay from A = 222, Z = 86?", ["A = 218, Z = 84", "A = 222, Z = 87", "A = 218, Z = 86", "A = 220, Z = 84"], 0, "Subtract 4 from A and 2 from Z.", ["decay_equation_balance_confusion"], skill_tags=["alpha_ledger"]),
        short("M13L6_C4", "Why is it weak to balance only one of the two counts in a decay equation?", ["Because both atomic number and mass number must balance; keeping only one correct is not enough.", "Because the ledger must conserve both the proton count and the total nucleon count together."], "Use both-counts language.", ["decay_equation_balance_confusion"], skill_tags=["balance_decay_equation"], acceptance_rules=acceptance_groups(["both", "two"], ["atomic number", "badge", "proton"], ["mass number", "total"], ["balance", "conserve"])) ,
        mcq("M13L6_C5", "A nucleus emits beta-minus radiation. If the parent has A = 14 and Z = 6, the daughter has...", ["A = 14 and Z = 7", "A = 10 and Z = 4", "A = 14 and Z = 6", "A = 15 and Z = 6"], 0, "Beta-minus raises Z by 1 and keeps A the same.", ["beta_mass_number_confusion", "decay_equation_balance_confusion"], skill_tags=["beta_ledger"]),
        short("M13L6_C6", "Why does the element change after alpha or beta-minus but not after gamma?", ["Because alpha and beta-minus change the proton count, while gamma does not.", "Because element identity follows atomic number, and only alpha or beta-minus change Z."], "Connect identity to proton number.", ["gamma_changes_numbers_confusion", "proton_identity_confusion", "decay_equation_balance_confusion"], skill_tags=["atomic_number"], acceptance_rules=acceptance_groups(["element", "identity"], ["proton", "badge", "atomic number", "Z"], ["alpha", "beta"], ["gamma"], ["change", "unchanged"])) ,
    ]
    t = [
        mcq("M13L6_M1", "A nucleus with A = 210 and Z = 84 emits alpha radiation. The daughter nucleus is...", ["A = 206 and Z = 82", "A = 210 and Z = 85", "A = 208 and Z = 84", "A = 206 and Z = 84"], 0, "Alpha removes 2 protons and 2 neutrons.", ["decay_equation_balance_confusion"], skill_tags=["alpha_ledger"]),
        mcq("M13L6_M2", "A nucleus with A = 90 and Z = 38 emits beta-minus radiation. The daughter nucleus is...", ["A = 90 and Z = 39", "A = 86 and Z = 36", "A = 90 and Z = 38", "A = 91 and Z = 38"], 0, "Beta-minus raises Z by 1 while A stays fixed.", ["beta_mass_number_confusion", "decay_equation_balance_confusion"], skill_tags=["beta_ledger"]),
        short("M13L6_M3", "A nucleus emits gamma radiation. What should you write for the daughter nucleus in the ledger?", ["Write the same atomic number and the same mass number for the daughter nucleus because gamma changes only the energy state.", "The daughter keeps the same Z and A because gamma does not remove a proton or neutron."], "Use same-Z-and-A language.", ["gamma_changes_numbers_confusion", "decay_equation_balance_confusion"], skill_tags=["gamma_ledger"], acceptance_rules=acceptance_groups(["same", "unchanged"], ["Z", "atomic number", "badge"], ["A", "mass number"], ["gamma"])) ,
        mcq("M13L6_M4", "Which statement best fixes the mistake 'beta-minus makes A go up because a particle is emitted'?", ["A stays the same because one neutron changes into one proton, so the total nucleon count is unchanged.", "A goes up because the emitted electron adds one more particle.", "A falls by 1 because an electron leaves.", "Both Z and A stay the same in beta-minus."], 0, "The nucleon total is unchanged in beta-minus.", ["beta_mass_number_confusion", "decay_equation_balance_confusion"], skill_tags=["beta_ledger"]),
        short("M13L6_M5", "Why does alpha decay always lower the mass number by 4?", ["Because an alpha particle contains 2 protons and 2 neutrons, so four nucleons leave the nucleus.", "Because alpha emission removes a 4-nucleon chunk from the parent nucleus."], "Connect alpha to a 4-nucleon cluster.", ["alpha_beta_gamma_mixup", "decay_equation_balance_confusion"], skill_tags=["alpha_ledger"], acceptance_rules=acceptance_groups(["alpha"], ["2 protons", "2 neutrons", "four nucleons", "4"], ["leave", "remove"])) ,
        mcq("M13L6_M6", "Which pair balances a gamma decay correctly?", ["same A and same Z on both sides, plus gamma emitted", "A - 4 and Z - 2 on the daughter side", "A same and Z + 1 on the daughter side", "different A because energy left"], 0, "Gamma leaves the counts unchanged.", ["gamma_changes_numbers_confusion", "decay_equation_balance_confusion"], skill_tags=["gamma_ledger"]),
        short("M13L6_M7", "A learner says, 'the daughter can have a different proton number even if the ledger still balances mass number.' What is the correction?", ["The ledger is only correct when both atomic number and mass number balance, so you cannot ignore the proton-number balance.", "Mass-number balance alone is not enough; atomic number must balance too because it tracks the proton count and the element."], "Correct with both-counts language.", ["decay_equation_balance_confusion", "proton_identity_confusion"], skill_tags=["balance_decay_equation"], acceptance_rules=acceptance_groups(["both", "atomic number", "mass number"], ["balance", "conserve"], ["not enough", "cannot ignore"], ["proton", "badge", "element"])) ,
        mcq("M13L6_M8", "Best summary of Lesson 6:", ["Decay equations work because atomic number and mass number both balance across alpha, beta, and gamma changes.", "Only mass number matters in a decay equation.", "Gamma always changes the element shown in the ledger.", "The ledger is separate from the real nuclear process."], 0, "The ledger is the balancing rule for the real process.", ["decay_equation_balance_confusion", "gamma_changes_numbers_confusion"], skill_tags=["balance_decay_equation"]),
    ]
    return lesson_spec(
        "M13_L6",
        "Vault Ledger Boss",
        sim("m13_vault_ledger_lab", "Vault Ledger lab", "Balance nuclear decay equations by tracking badge count and total core-piece count.", ["Choose alpha, beta-minus, or gamma.", "Apply the correct change rule.", "Check that both counts balance across the arrow."], ["Balance simple decay equations.", "Explain why alpha, beta, and gamma change the ledger differently.", "Use atomic number and mass number carefully."], ["decay_type", "parent_atomic_number", "parent_mass_number", "daughter_guess"], "Decay-equation reasoning."),
        d,
        "The Vault Ledger is the before-and-after record that proves the decay story still balances. Every nuclear equation must keep both the badge count and the total core-piece count balanced across the arrow, even though alpha, beta-minus, and gamma do that in different ways.",
        "Read the signal first, apply its count-change rule second, and then check both counts before trusting the ledger.",
        [prompt_block("Which two totals must balance in every decay ledger?", "Atomic number and mass number."), prompt_block("Which signal changes neither of those totals?", "Gamma.")],
        [prompt_block("Start with an alpha decay.", "Lower Z by 2 and A by 4."), prompt_block("Now compare a beta-minus decay.", "Raise Z by 1 while keeping A unchanged.")],
        ["Why must the Vault Ledger balance both atomic number and mass number?", "Why does gamma emission leave the ledger counts unchanged?"],
        "Use the ledger so the decay equation becomes a balancing check, not a memorized symbol pattern.",
        c,
        t,
        contract(
            concept_targets=["Balance simple alpha, beta-minus, and gamma decay equations.", "Explain why atomic number and mass number must both balance.", "Use proton-number identity to explain when the element changes."],
            core_concepts=["Atomic number tracks proton count and therefore element identity.", "Mass number tracks the total nucleon count.", "Alpha lowers Z by 2 and A by 4.", "Beta-minus raises Z by 1 while leaving A unchanged.", "Gamma leaves both counts unchanged because it releases energy only."],
            prerequisite_lessons=["M13_L1", "M13_L3"],
            misconception_focus=["decay_equation_balance_confusion", "beta_mass_number_confusion", "gamma_changes_numbers_confusion", "proton_identity_confusion"],
            formulas=[relation("alpha: parent -> daughter with Z - 2 and A - 4", "Alpha emission removes a 2-proton, 2-neutron chunk.", ["change rule"], "Use when balancing alpha decay equations."), relation("beta-minus: parent -> daughter with Z + 1 and A unchanged", "Beta-minus converts one neutron to one proton while keeping nucleon total the same.", ["change rule"], "Use when balancing beta-minus equations."), relation("gamma: parent* -> parent + gamma with Z unchanged and A unchanged", "Gamma emission changes the energy state only.", ["change rule"], "Use when balancing gamma equations.")],
            representations=[representation("words", "Explains why the ledger must balance both counts."), representation("diagram", "Shows alpha, beta, and gamma count changes side by side."), representation("formula", "Uses Z and A in formal nuclear equations."), representation("table", "Compares the balancing rule for alpha, beta-minus, and gamma side by side.")],
            analogy_map=core_vault_map("the class is balancing the before-and-after ledger for alpha, beta, and gamma changes"),
            worked_examples=[worked("A parent nucleus has A = 222 and Z = 86 and emits alpha radiation. What are the daughter numbers?", ["Apply the alpha rule: subtract 2 from Z.", "Subtract 4 from A.", "State the daughter nucleus numbers."], "daughter: A = 218, Z = 84", "Alpha removes 2 protons and 2 neutrons, so both counts must fall.", "This is the cleanest alpha-ledger pattern."), worked("A parent nucleus has A = 14 and Z = 6 and emits beta-minus radiation. What are the daughter numbers?", ["Apply the beta-minus rule.", "Increase Z by 1.", "Keep A unchanged."], "daughter: A = 14, Z = 7", "Beta-minus changes one neutron into one proton, so Z rises but A stays the same.", "This blocks the common beta mass-number mistake."), worked("A parent nucleus emits gamma radiation. What must the daughter numbers be?", ["Ask whether any proton or neutron leaves.", "Notice that gamma is energy only.", "Keep both counts unchanged in the daughter nucleus."], "The daughter keeps the same A and Z.", "Gamma changes the energy state without changing the proton or nucleon counts.", "This keeps gamma separate from alpha and beta bookkeeping.")],
            visual_assets=[visual("m13-l6-vault-ledger", "vault_ledger", "Vault Ledger Boss", "Shows alpha, beta, and gamma count balancing side by side in one decay ledger.", "The before-and-after count changes must stay readable at a glance.")],
            animation_assets=[animation("m13-l6-ledger-balance", "vault_ledger", "Ledger balance", "Shows alpha, beta, and gamma updates being written into the decay ledger while the counts are checked.")],
            simulation_contract=sim_contract("m13-l6-vault-ledger-lab", "vault_ledger", "How do you keep the decay ledger balanced when alpha, beta-minus, and gamma all change the nucleus differently?", "Start with one parent nucleus and balance one alpha case before trying beta-minus and gamma.", ["Switch between alpha, beta-minus, and gamma.", "Check whether both atomic number and mass number still balance.", "Explain which decays change the element and why."], "Do not balance only one count and assume the equation is correct.", "The decay ledger works only when both atomic number and mass number are conserved across the arrow.", [("decay_type", "Decay type", "Chooses which radiation rule to apply."), ("parent_atomic_number", "Parent atomic number", "Tracks the proton count before decay."), ("parent_mass_number", "Parent mass number", "Tracks the total nucleon count before decay.")], [("Daughter numbers", "Shows the balanced daughter nucleus."), ("Ledger check", "Confirms whether both counts balance."), ("Element change", "Explains whether the proton count changed.")]),
            reflection_prompts=["Why must the Vault Ledger balance both atomic number and mass number?", "Why does gamma emission leave the ledger counts unchanged?"],
            mastery_skills=["balance_decay_equation", "alpha_ledger", "beta_ledger", "gamma_ledger", "atomic_number"],
            variation_plan={"diagnostic": "Fresh attempts rotate between ledger meaning, alpha or beta-minus change rules, and gamma-not-changing-counts stems.", "concept_gate": "Concept checks vary between direct balancing, both-counts explanations, and element-identity reasoning.", "mastery": "Mastery mixes numeric daughter-nucleus questions with short explanations before repeating any stem."},
            scaffold_support=scaffold("The Vault Ledger is correct only when both atomic number and mass number balance across the arrow.", "Name the decay type first, apply its rule second, and then check both counts before accepting the daughter nucleus.", "If gamma is emitted, what should happen to Z and A in the ledger?", "Do not check only one number and assume the whole equation is correct.", "The ledger works like strict bookkeeping: every badge and every total core-piece count must still be accounted for after the vault settles.", "Why is balancing only the mass number weaker than balancing both counts?", [extra_section("Element identity", "If the proton number changes, the element changes because identity follows Z.", "Which decay types can change the element in the school model?"), extra_section("Three ledger rules", "Alpha changes both counts, beta-minus changes Z only, and gamma changes neither count.", "Which rule belongs to beta-minus?")]),
            visual_clarity_checks=visual_checks("vault-ledger"),
        ),
    )


M13_SPEC = {
    "authoring_standard": AUTHORING_STANDARD_V3,
    "module_description": "Atomic structure, isotopes, radiation types, half-life, background radiation, and decay equations taught through the Core-Vault Model so students keep identity, stability, decay, detector readings, and nuclear bookkeeping inside one coherent world.",
    "mastery_outcomes": [
        "Describe atomic structure using nucleus and outer electron region language.",
        "Explain isotopes as atoms of the same element with different neutron numbers.",
        "Distinguish alpha, beta, and gamma radiation using count-change and shielding language.",
        "Explain half-life as a statistical decay pattern for large groups of nuclei.",
        "Explain background radiation as a normal environmental presence and correct detector readings by subtracting background.",
        "Balance simple nuclear decay equations using atomic number and mass number.",
    ],
    "lessons": [
        vault_house_lesson(),
        isotope_lesson(),
        escape_lesson(),
        half_life_lesson(),
        background_lesson(),
        ledger_lesson(),
    ],
}


RELEASE_CHECKS = [
    "Every lesson keeps the Core-Vault world of badges, stones, escape signals, Settle Span, Ambient Buzz, and the Vault Ledger coherent.",
    "Every explorer is lesson-specific in focus even when it uses the generic simulation shell.",
    "Every lesson-owned bank supports fresh unseen diagnostic, concept-gate, and mastery questions before repeats.",
    "Every conceptual short answer accepts varied scientifically correct wording through authored phrase groups.",
    "Every worked example includes answer reasoning and not just a final value.",
    "Every visual keeps nucleus, isotope, radiation, half-life, background, and ledger labels readable without clipping or count collapse.",
]


M13_MODULE_DOC, M13_LESSONS, M13_SIM_LABS = build_nextgen_module_bundle(
    module_id=M13_MODULE_ID,
    module_title=M13_MODULE_TITLE,
    module_spec=M13_SPEC,
    allowlist=M13_ALLOWLIST,
    content_version=M13_CONTENT_VERSION,
    release_checks=RELEASE_CHECKS,
    sequence=17,
    level="Module 13",
    estimated_minutes=320,
    authoring_standard=AUTHORING_STANDARD_V3,
    plan_assets=True,
    public_base="/lesson_assets",
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed Module M13 into Firestore")
    parser.add_argument("--project", default=None)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--compile-assets", action="store_true")
    parser.add_argument("--asset-root", default="")
    parser.add_argument("--public-base", default="/lesson_assets")
    args = parser.parse_args()

    project = get_project_id(args.project)
    init_firebase(project)
    asset_root = args.asset_root or default_asset_root()
    module_doc = deepcopy(M13_MODULE_DOC)
    lesson_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in M13_LESSONS]
    sim_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in M13_SIM_LABS]

    if args.compile_assets:
        render_module_assets(lesson_pairs, sim_pairs, asset_root=asset_root, public_base=args.public_base)

    print_preview(module_doc, lesson_pairs, sim_pairs)
    db = init_firebase(project)
    plan: List[Tuple[str, str]] = [("modules", M13_MODULE_ID)]
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


if __name__ == "__main__":
    main()
