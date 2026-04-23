import os
import base64
import pyotp
import qrcode
from io import BytesIO
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, field_validator

app = FastAPI(title="2FA Auth System", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

hasher = CryptContext(schemes=["bcrypt"], deprecated="auto")

JWT_SECRET = os.getenv("JWT_SECRET", "change-this-before-any-real-deployment")
JWT_ALGO = "HS256"
TOKEN_LIFETIME = 30

token_scheme = OAuth2PasswordBearer(tokenUrl="login")

user_store: dict = {}


class RegisterRequest(BaseModel):
    username: str
    password: str

    @field_validator("username", "password")
    @classmethod
    def not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("field cannot be empty")
        return v


class VerifyRequest(BaseModel):
    username: str
    totp_code: str


class LoginRequest(BaseModel):
    username: str
    password: str
    totp_code: str


def encrypt_password(raw: str) -> str:
    return hasher.hash(raw)


def check_password(raw: str, encrypted: str) -> bool:
    return hasher.verify(raw, encrypted)


def build_qr(username: str, otp_secret: str) -> str:
    uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(
        name=username,
        issuer_name="2FA Auth System",
    )
    img = qrcode.make(uri)
    buf = BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


def mint_token(payload: dict) -> str:
    data = payload.copy()
    data["exp"] = datetime.now(timezone.utc) + timedelta(minutes=TOKEN_LIFETIME)
    return jwt.encode(data, JWT_SECRET, algorithm=JWT_ALGO)


def extract_user(token: str = Depends(token_scheme)) -> str:
    error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Session expired or invalid",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        claims = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        username = claims.get("sub")
        if not username or username not in user_store:
            raise error
    except JWTError:
        raise error
    return username


@app.get("/")
def home():
    return {"status": "online", "version": "1.0.0"}


@app.post("/register")
def register(body: RegisterRequest):
    if body.username in user_store:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="That username is already taken",
        )
    otp_secret = pyotp.random_base32()
    user_store[body.username] = {
        "password": encrypt_password(body.password),
        "otp_secret": otp_secret,
        "verified": False,
    }
    return {
        "message": f"Account created for '{body.username}'. Scan the QR code to activate 2FA.",
        "qr_code": build_qr(body.username, otp_secret),
        "secret": otp_secret,
    }


@app.post("/verify-2fa")
def verify_2fa(body: VerifyRequest):
    if body.username not in user_store:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account not found")
    record = user_store[body.username]
    if not pyotp.TOTP(record["otp_secret"]).verify(body.totp_code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Code did not match — try again",
        )
    user_store[body.username]["verified"] = True
    return {"message": "2FA is now active on your account.", "status": "verified"}


@app.post("/login")
def login(body: LoginRequest):
    if body.username not in user_store:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account not found")
    record = user_store[body.username]
    if not record["verified"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Complete 2FA setup before logging in",
        )
    if not check_password(body.password, record["password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect password")
    if not pyotp.TOTP(record["otp_secret"]).verify(body.totp_code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid 2FA code — check your authenticator app",
        )
    return {
        "access_token": mint_token({"sub": body.username}),
        "token_type": "bearer",
    }


@app.get("/dashboard")
def dashboard(active_user: str = Depends(extract_user)):
    return {
        "message": f"Authenticated as {active_user}.",
        "security": "Password verified + 2FA code verified",
        "data": "Protected endpoint — both factors confirmed.",
    }