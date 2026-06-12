import os
import base64
from io import BytesIO
from datetime import datetime, timedelta, timezone

import pyotp
import qrcode

from fastapi import FastAPI, HTTPException, status, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, field_validator
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="2FA Auth System", version="1.0.0")
app.state.limiter = limiter


def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    # Return the 429 under a "detail" key so the frontend (which reads data.detail)
    # surfaces it the same way as every other error.
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={"detail": "Too many requests. Slow down and try again in a minute."},
    )


app.add_exception_handler(RateLimitExceeded, rate_limit_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: lock to the known frontend origin in production
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

hasher = CryptContext(schemes=["bcrypt"], deprecated="auto")

JWT_SECRET = os.getenv("JWT_SECRET", "change-this-before-any-real-deployment")
JWT_ALGO = "HS256"
TOKEN_LIFETIME = 30
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

token_scheme = OAuth2PasswordBearer(tokenUrl="login")

# In-memory stores: reset on restart, not shared across workers. Fine for a demo;
# production would use a database + shared cache (e.g. Redis).
user_store: dict = {}
# username -> {"count": int, "locked_until": datetime | None}
failed_attempts: dict = {}

# Pre-hashed placeholder used to keep timing constant when a username doesn't
# exist, so accounts can't be enumerated by how fast the server rejects a login.
_DUMMY_HASH = hasher.hash("constant-time-placeholder")


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


# bcrypt hashes a password; it does not encrypt it (you can't get the original
# back). Naming these honestly matters in a security project.
def hash_password(raw: str) -> str:
    return hasher.hash(raw)


def verify_password(raw: str, hashed: str) -> bool:
    return hasher.verify(raw, hashed)


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


def is_locked(username: str) -> bool:
    record = failed_attempts.get(username)
    if not record:
        return False
    locked_until = record.get("locked_until")
    if locked_until is None:
        return False
    if datetime.now(timezone.utc) < locked_until:
        return True
    failed_attempts.pop(username, None)  # window passed, clear it
    return False


def register_failure(username: str) -> None:
    record = failed_attempts.get(username, {"count": 0, "locked_until": None})
    record["count"] += 1
    if record["count"] >= MAX_FAILED_ATTEMPTS:
        record["locked_until"] = datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES)
    failed_attempts[username] = record


def reset_failures(username: str) -> None:
    failed_attempts.pop(username, None)


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


@app.post("/register", status_code=status.HTTP_201_CREATED)
@limiter.limit("10/minute")
def register(request: Request, body: RegisterRequest):
    if body.username in user_store:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="That username is already taken",
        )
    otp_secret = pyotp.random_base32()
    user_store[body.username] = {
        "password": hash_password(body.password),
        "otp_secret": otp_secret,
        "verified": False,
        "last_totp": None,
    }
    return {
        "message": f"Account created for '{body.username}'. Scan the QR code to activate 2FA.",
        "qr_code": build_qr(body.username, otp_secret),
        # Shown once for manual entry. The QR encodes this same value — this is
        # standard TOTP enrollment, not a leak.
        "secret": otp_secret,
    }


@app.post("/verify-2fa")
@limiter.limit("5/minute")
def verify_2fa(request: Request, body: VerifyRequest):
    # Same response whether the account is missing or the code is wrong, so this
    # endpoint can't be used to probe which usernames exist.
    failure = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Verification failed. Check the code and try again.",
    )
    record = user_store.get(body.username)
    if record is None:
        raise failure
    if not pyotp.TOTP(record["otp_secret"]).verify(body.totp_code):
        raise failure
    record["verified"] = True
    return {"message": "2FA is now active on your account.", "status": "verified"}


@app.post("/login")
@limiter.limit("5/minute")
def login(request: Request, body: LoginRequest):
    invalid = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid username, password, or code",
    )

    if is_locked(body.username):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Account temporarily locked after repeated failures. Try again later.",
        )

    record = user_store.get(body.username)
    if record is None:
        verify_password(body.password, _DUMMY_HASH)  # equalise timing
        register_failure(body.username)
        raise invalid

    # Factor 1: password. Kept generic so a wrong password reveals nothing.
    if not verify_password(body.password, record["password"]):
        register_failure(body.username)
        raise invalid

    # Password is correct from here, so it's safe to tell the legitimate user
    # their 2FA setup isn't finished.
    if not record["verified"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Finish 2FA setup before logging in.",
        )

    # Factor 2: TOTP.
    if not pyotp.TOTP(record["otp_secret"]).verify(body.totp_code):
        register_failure(body.username)
        raise invalid

    # Replay guard: a TOTP code is valid for its ~30s window, so reject reuse of
    # the exact code we last accepted. Not counted as a failure (could be a
    # legitimate double-submit), just refused.
    if record.get("last_totp") == body.totp_code:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="That code was already used. Wait for the next one.",
        )

    record["last_totp"] = body.totp_code
    reset_failures(body.username)
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