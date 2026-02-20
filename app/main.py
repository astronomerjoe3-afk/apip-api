from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
import firebase_admin
from firebase_admin import auth, credentials
from fastapi import Depends
from app.dependencies import get_current_user

app = FastAPI()

# CORS: allow your frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.cognispark.tech", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Firebase Admin using ADC (works on Cloud Run)
# Locally, run: gcloud auth application-default login
if not firebase_admin._apps:
    cred = credentials.ApplicationDefault()
    firebase_admin.initialize_app(cred)

def get_current_user(authorization: str | None = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    token = authorization.split(" ", 1)[1].strip()
    try:
        decoded = auth.verify_id_token(token)
        return decoded  # includes uid, email (if available), etc.
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.get("/me")
def me(user=Depends(get_current_user)):
    return {
        "uid": user.get("uid"),
        "email": user.get("email"),
        "provider": user.get("firebase", {}).get("sign_in_provider"),
    }

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/profile")
async def profile(user=Depends(get_current_user)):
    return {
        "message": "Secure profile",
        "uid": user["uid"],
        "email": user.get("email"),
    }
