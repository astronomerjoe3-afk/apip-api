import firebase_admin
from firebase_admin import auth

# On Cloud Run, firebase_admin uses Application Default Credentials (ADC)
# from the service account. No JSON key file needed.
if not firebase_admin._apps:
    firebase_admin.initialize_app()

def verify_token(id_token: str):
    return auth.verify_id_token(id_token)