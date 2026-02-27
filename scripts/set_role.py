import os
import argparse
import firebase_admin
from firebase_admin import credentials, auth, firestore

# ---------- CONFIG ----------
PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT", "apip-dev-487809-c949c")
# ----------------------------


def initialize_firebase():
    if not firebase_admin._apps:
        cred = credentials.ApplicationDefault()
        firebase_admin.initialize_app(cred, {"projectId": PROJECT_ID})


def resolve_uid(uid: str | None, email: str | None) -> str:
    if uid:
        return uid
    if not email:
        raise ValueError("Must provide --uid or --email")

    user = auth.get_user_by_email(email)
    return user.uid


def set_role(uid: str, role: str):
    print(f"Setting role '{role}' for UID: {uid}")
    auth.set_custom_user_claims(uid, {"role": role})
    print("✅ Custom claim set successfully.")


def verify_role(uid: str):
    user = auth.get_user(uid)
    print("🔎 Current custom claims:", user.custom_claims)
    print("🆔 UID:", user.uid)
    print("📧 Email:", user.email)


def create_or_update_user_doc(uid: str, role: str):
    db = firestore.client()
    user_ref = db.collection("users").document(uid)

    user_ref.set(
        {
            "uid": uid,
            "role": role,
            "createdByScript": True,
        },
        merge=True,
    )
    print("📄 Firestore user document created/updated.")


def main():
    parser = argparse.ArgumentParser(description="Set Firebase user role")
    parser.add_argument("--uid", help="Firebase UID")
    parser.add_argument("--email", help="User email (will resolve UID)")
    parser.add_argument("--role", default="admin", help="Role to assign")
    parser.add_argument(
        "--provision-user-doc",
        action="store_true",
        help="Also create/update Firestore user document",
    )

    args = parser.parse_args()

    initialize_firebase()

    try:
        uid = resolve_uid(args.uid, args.email)
    except Exception as e:
        raise SystemExit(f"ERROR: {e}")

    set_role(uid, args.role)
    verify_role(uid)

    if args.provision_user_doc:
        create_or_update_user_doc(uid, args.role)


if __name__ == "__main__":
    main()