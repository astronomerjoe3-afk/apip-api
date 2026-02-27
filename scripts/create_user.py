import os
import argparse
import firebase_admin
from firebase_admin import credentials, auth, firestore

PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT", "apip-dev-487809-c949c")


def initialize_firebase():
    if not firebase_admin._apps:
        cred = credentials.ApplicationDefault()
        firebase_admin.initialize_app(cred, {"projectId": PROJECT_ID})


def provision_user_doc(uid: str, email: str, role: str):
    db = firestore.client()
    db.collection("users").document(uid).set(
        {
            "uid": uid,
            "email": email,
            "role": role,
            "createdByScript": True,
        },
        merge=True,
    )


def main():
    parser = argparse.ArgumentParser(description="Create Firebase Auth user + set role claim")
    parser.add_argument("--email", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--role", default="student", choices=["student", "instructor", "admin"])
    parser.add_argument("--provision-user-doc", action="store_true")

    args = parser.parse_args()

    initialize_firebase()

    # If user already exists, just reuse it
    try:
        u = auth.get_user_by_email(args.email)
        print(f"User already exists: {u.uid} ({u.email})")
        user = u
    except Exception:
        user = auth.create_user(email=args.email, password=args.password)
        print(f"✅ Created user: {user.uid} ({user.email})")

    auth.set_custom_user_claims(user.uid, {"role": args.role})
    print(f"✅ Set role claim: {args.role}")

    if args.provision_user_doc:
        provision_user_doc(user.uid, args.email, args.role)
        print("📄 Provisioned Firestore users/{uid}")

    print("DONE")
    print("UID:", user.uid)


if __name__ == "__main__":
    main()