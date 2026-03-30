from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from pydantic import BaseModel
from jose import JWTError, jwt
from datetime import datetime, timedelta
import pyotp
import qrcode
import base64
from io import BytesIO

app = FastAPI(
    title="2FA Auth System",
    description="Authentication API with Two Factor verification via Google Authenticator",
    version="1.0.0"
)

# Allow frontend requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# bcrypt for password security
hasher = CryptContext(schemes=["bcrypt"], deprecated="auto")

JWT_SECRET = "change-this-in-production-please" # WARNING: Move this to an environment variable before any real deployment
JWT_ALGO = "HS256"
TOKEN_LIFETIME = 30 # Token expires after 30 minutes

token_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Simple in-memory store — will upgrade to real DB later
user_store = {}

# --- Request Models ---
class RegisterRequest(BaseModel):
    username: str
    password: str

class VerifyRequest(BaseModel):
    username: str
    totp_code: str

class LoginRequest(BaseModel):
    username: str
    password: str
    totp_code: str

def encrypt_password(raw: str):
    return hasher.hash(raw)

def check_password(raw: str, encrypted: str):
    return hasher.verify(raw, encrypted)

def build_qr(username: str, otp_secret: str):
    # Build URI that Google Authenticator can read
    uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(
        name=username,
        issuer_name="2FA Auth System"
    )
    img = qrcode.make(uri)
    buf = BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()

def mint_token(payload: dict):
    data = payload.copy()
    data["exp"] = datetime.utcnow() + timedelta(minutes=TOKEN_LIFETIME)
    return jwt.encode(data, JWT_SECRET, algorithm=JWT_ALGO)

def extract_user(token: str = Depends(token_scheme)):
    error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Session expired or invalid",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        claims = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        username = claims.get("sub")
        if not username:
            raise error
    except JWTError:
        raise error
    if username not in user_store:
        raise error
    return username

@app.get("/")
def home():
    return {
        "message": "2FA Auth System by Shrish",
        "version": "1.0",
        "status": "online"
    }

@app.post("/register")
def register(body: RegisterRequest):
    if body.username in user_store:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="That username is already taken"
        )

    # Each user gets their own OTP secret
    otp_secret = pyotp.random_base32()

    user_store[body.username] = {
        "username": body.username,
        "password": encrypt_password(body.password),
        "otp_secret": otp_secret,
        "verified": False
    }

    return {
        "message": f"Welcome {body.username}! Scan the QR code to activate 2FA.",
        "instruction": "Open Google Authenticator and scan below",
        "qr_code": build_qr(body.username, otp_secret),
        "secret": otp_secret
    }

@app.post("/verify-2fa")
def verify_2fa(body: VerifyRequest):
    if body.username not in user_store:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Account not found"
        )

    record = user_store[body.username]
    checker = pyotp.TOTP(record["otp_secret"])

    if not checker.verify(body.totp_code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="That code didn't match — try again"
        )

    # Mark account as 2FA verified
    user_store[body.username]["verified"] = True

    return {
        "message": f"2FA is now active on your account!",
        "status": "verified"
    }

@app.post("/login")
def login(body: LoginRequest):
    if body.username not in user_store:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No account found with that username"
        )

    record = user_store[body.username]

    # Must complete 2FA setup before logging in
    if not record["verified"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Please complete your 2FA setup first"
        )

    # Wrong password
    if not check_password(body.password, record["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password"
        )

    # Wrong OTP code
    checker = pyotp.TOTP(record["otp_secret"])
    if not checker.verify(body.totp_code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid 2FA code — check your authenticator app"
        )

    # All good — issue token
    token = mint_token({"sub": body.username})
    return {
        "message": f"Hey {body.username}, you're in!",
        "access_token": token,
        "token_type": "bearer"
    }

@app.get("/dashboard")
def dashboard(active_user: str = Depends(extract_user)):
    return {
        "message": f"Welcome {active_user}, both factors verified!",
        "security": "Password ✅ + 2FA Code ✅",
        "data": "You have successfully accessed the protected area."
    }