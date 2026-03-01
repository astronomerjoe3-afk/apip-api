import firebase_admin
from firebase_admin import firestore

def main():
    if not firebase_admin._apps:
        firebase_admin.initialize_app()
    db = firestore.client()

    print("Firestore project:", db.project)

    mod_ref = db.collection("modules").document("F1")
    mod = mod_ref.get()
    print("modules/F1 exists:", mod.exists)

    l1_sub = mod_ref.collection("lessons").document("F1-L1").get()
    print("modules/F1/lessons/F1-L1 exists:", l1_sub.exists)

    l1_top = db.collection("lessons").document("F1-L1").get()
    print("lessons/F1-L1 exists:", l1_top.exists)

    if l1_sub.exists:
        d = l1_sub.to_dict()
        print("Has phases:", "phases" in d)
        if "phases" in d:
            print("Has analogy_text:", bool(d["phases"].get("analogical_grounding", {}).get("analogy_text")))
            print("Has inquiry_prompts:", len(d["phases"].get("simulation_inquiry", {}).get("inquiry_prompts", [])))
            print("Has capsules:", len(d["phases"].get("concept_reconstruction", {}).get("capsules", [])))

if __name__ == "__main__":
    main()
