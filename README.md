# 2FA Authentication System

Two-factor authentication system built with FastAPI, implementing TOTP-based login, bcrypt password hashing, and JWT session management — integrated with Google Authenticator.

Built by Shrish Arunesh — CS student in Berlin, focused on cybersecurity and backend development.

---

## Live Demo

| | |
|---|---|
| Frontend | [shashquash.github.io/2fa-auth-system/frontend](https://shashquash.github.io/2fa-auth-system/frontend) |
| API Docs | [twofa-auth-system.onrender.com/docs](https://twofa-auth-system.onrender.com/docs) |

---

## Stack

Python · FastAPI · pyotp · qrcode · bcrypt · JWT · HTML · CSS · JavaScript

---

## How 2FA Works

1. User registers → server generates a unique TOTP secret key
2. Secret key is encoded into a QR code
3. User scans QR code with Google Authenticator
4. Phone and server now share the same secret — neither transmits it again
5. Every 30 seconds both independently generate the same 6-digit code (RFC 6238)
6. At login — user submits password + current 6-digit code
7. Server verifies both → issues JWT token

---

## API Endpoints

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/` | Status check | No |
| POST | `/register` | Register + receive QR code | No |
| POST | `/verify-2fa` | Confirm TOTP setup | No |
| POST | `/login` | Login with password + TOTP | No |
| GET | `/dashboard` | Protected endpoint | Yes |

---

## Running Locally

```bash
git clone https://github.com/ShashQuash/2fa-auth-system.git
cd 2fa-auth-system
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # macOS / Linux
pip install -r requirements.txt
python -m uvicorn main:app --reload
```

API at `http://127.0.0.1:8000` · Docs at `http://127.0.0.1:8000/docs`

Open `frontend/index.html` with Live Server in VS Code to use the frontend.

---

## Project Structure

```
2fa-auth-system/
├── main.py
├── requirements.txt
├── README.md
└── frontend/
    └── index.html
```

---

## Author

Shrish Arunesh · [Portfolio](https://shashquash.github.io/portfolio) · [GitHub](https://github.com/ShashQuash)