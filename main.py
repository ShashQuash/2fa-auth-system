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

# App setup
app = FastAPI(
    title="2FA Authentication System",
    description="Secure authentication with Two Factor Authentication",
    version="1.0.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Password hasher
password_hasher = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT configuration
SECRET_KEY = "2fa-super-secret-key-change-in-production"
ALGORITHM = "HS256"
TOKEN_EXPIRY_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# In-memory database
users_db = {}

# --- Models ---
class UserRegister(BaseModel):
    username: str
    password: str

class UserVerify(BaseModel):
    username: str
    totp_code: str

class UserLogin(BaseModel):
    username: str
    password: str
    totp_code: str

# --- Helper Functions ---
def hash_password(password: str):
    return password_hasher.hash(password)

def verify_password(plain: str, hashed: str):
    return password_hasher.verify(plain, hashed)

def generate_qr_code(username: str, secret: str):
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name="2FA Auth System"
    )
    qr = qrcode.make(totp_uri)
    buffer = BytesIO()
    qr.save(buffer, format="PNG")
    qr_base64 = base64.b64encode(buffer.getvalue()).decode()
    return qr_base64

def generate_token(data: dict):
    token_data = data.copy()
    expiry = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRY_MINUTES)
    token_data.update({"exp": expiry})
    token = jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)
    return token

def get_current_user(token: str = Depends(oauth2_scheme)):
    auth_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise auth_error
    except JWTError:
        raise auth_error
    if username not in users_db:
        raise auth_error
    return username

# --- Endpoints ---
@app.get("/")
def read_root():
    return {
        "message": "2FA Authentication System by Shrish",
        "version": "1.0",
        "status": "running"
    }

@app.post("/register")
def register(user: UserRegister):
    if user.username in users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already taken"
        )
    secret = pyotp.random_base32()
    users_db[user.username] = {
        "username": user.username,
        "hashed_password": hash_password(user.password),
        "totp_secret": secret,
        "2fa_enabled": False
    }
    qr_code = generate_qr_code(user.username, secret)
    return {
        "message": f"Account created for '{user.username}'!",
        "instruction": "Scan this QR code with Google Authenticator",
        "qr_code": qr_code,
        "secret": secret
    }

@app.post("/verify-2fa")
def verify_2fa(data: UserVerify):
    if data.username not in users_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    user_record = users_db[data.username]
    totp = pyotp.TOTP(user_record["totp_secret"])
    if not totp.verify(data.totp_code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid 2FA code. Please try again."
        )
    users_db[data.username]["2fa_enabled"] = True
    return {
        "message": f"2FA successfully enabled for '{data.username}'!",
        "status": "2FA verified and active"
    }

# NEW — Full login endpoint with 2FA
@app.post("/login")
def login(user: UserLogin):
    # Step 1 — Check if user exists
    if user.username not in users_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    user_record = users_db[user.username]

    # Step 2 — Check if 2FA is enabled
    if not user_record["2fa_enabled"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Please complete 2FA setup first"
        )

    # Step 3 — Verify password
    if not verify_password(user.password, user_record["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password"
        )

    # Step 4 — Verify TOTP code from phone
    totp = pyotp.TOTP(user_record["totp_secret"])
    if not totp.verify(user.totp_code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid 2FA code. Please try again."
        )

    # Step 5 — All checks passed — generate JWT token
    access_token = generate_token(data={"sub": user.username})
    return {
        "message": f"Welcome back {user.username}! 2FA verified successfully.",
        "access_token": access_token,
        "token_type": "bearer"
    }

# Protected dashboard
@app.get("/dashboard")
def dashboard(current_user: str = Depends(get_current_user)):
    return {
        "message": f"Hey {current_user}, your identity has been fully verified!",
        "security": "Password ✅ + 2FA Code ✅",
        "data": "You are accessing protected data with 2FA security."
    }