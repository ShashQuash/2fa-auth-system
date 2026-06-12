# Two-Factor Authentication System

A FastAPI backend that adds TOTP-based 2FA on top of password login, the same kind Google Authenticator and Authy use. Password plus a rotating 6-digit code, with the brute-force and replay defenses that a second factor actually needs to be worth having.

Built by Shrish Arunesh, a CS student in Berlin working in backend and security.

## Live Demo

Frontend: [shashquash.github.io/2fa-auth-system/frontend](https://shashquash.github.io/2fa-auth-system/frontend)
API docs: [twofa-auth-system.onrender.com/docs](https://twofa-auth-system.onrender.com/docs)

Heads up: the backend sleeps on a free tier, so the first request after a quiet spell can take around 50 seconds to wake up. Give it a second and retry.

## Stack

Python, FastAPI, bcrypt (via passlib), pyotp for TOTP, qrcode for enrollment, python-jose for JWT, SlowAPI for rate limiting. Plain HTML/CSS/JS frontend.

## How the flow works

1. Register with a username and password. The server creates a TOTP secret and hands back a QR code.
2. Scan the QR with any authenticator app, or type the secret in manually if you can't scan.
3. Enter the 6-digit code once to confirm the app and server are in sync. That activates 2FA.
4. From then on, login needs all three: username, password, and the current code.

## What it does

**Passwords** are hashed with bcrypt before storage. The plaintext is never saved. (The functions are named `hash_password` / `verify_password` on purpose. bcrypt hashes, it doesn't encrypt, and the difference matters.)

**TOTP enrollment** generates a per-user secret and a scannable QR code. The secret is shown once during setup for manual entry, which is exactly how authenticator apps expect it. After that it's never sent back.

**Login** checks the password first, then the TOTP code, and only issues a JWT (30-minute expiry) when both pass.

**Rate limiting** caps login and verification at 5 requests per minute per IP. A 6-digit code is only a million combinations, so without this it's brute-forceable. With it, it isn't.

**Account lockout** triggers after 5 failed logins and lasts 15 minutes, then clears itself. No permanent locks from a few typos.

**Replay protection** rejects a code that was just used. TOTP codes stay valid for their full 30-second window, so without this an attacker who sniffs one code could reuse it. The server remembers the last accepted code and refuses a repeat.

**No username leaks.** Failed logins and failed verifications return the same generic error whether the account exists or not, and a login for a missing user still runs a throwaway hash check so you can't tell real usernames apart by timing. The one exception is after a correct password: an unverified account is told to finish 2FA setup, but that only ever reaches someone who already has the right password.

## Endpoints

| Method | Endpoint | What it does | Auth |
|--------|----------|--------------|------|
| GET | `/` | Health check | No |
| POST | `/register` | Create an account, get a QR code (201) | No |
| POST | `/verify-2fa` | Confirm the first code, activate 2FA | No |
| POST | `/login` | Password + TOTP, get a JWT (200) | No |
| GET | `/dashboard` | Example protected route | Yes |

Errors you'll see: `401` for bad credentials, a bad code, a reused code, or a bad token; `403` if the password is right but 2FA isn't set up yet; `409` if the username is taken; `429` if the account is locked or you've hit the rate limit.

## What it doesn't do (yet)

Being upfront about the gaps:

- The TOTP secret is stored as-is in memory. For a demo that's fine, but a real build would encrypt it at rest with a key kept outside the database.
- Users and lockout state live in memory, so they reset on restart and won't work across multiple workers. Production would use a database plus something like Redis.
- The lockout is keyed on username, so someone could deliberately lock a known account for 15 minutes. The per-IP rate limit softens it; the fuller fix is keying on IP plus username.
- No backup codes or device recovery. Lose the authenticator, lose access. A real product needs a recovery path.
- The frontend keeps the JWT in `localStorage`, which is exposed to XSS. An HttpOnly cookie would be safer.

## Running it locally

```bash
git clone https://github.com/ShashQuash/2fa-auth-system.git
cd 2fa-auth-system
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # macOS / Linux
pip install -r requirements.txt
python -m uvicorn main:app --reload
```

API runs at `http://127.0.0.1:8000`, docs at `/docs`. Open `frontend/index.html` with Live Server to use the UI. You'll want an authenticator app on your phone to test the full flow.

Set a real signing key before deploying anywhere:

```bash
$env:JWT_SECRET = "your-long-random-secret"   # PowerShell
export JWT_SECRET="your-long-random-secret"    # macOS / Linux
```

## Layout

```
2fa-auth-system/
├── main.py            # the whole API: auth, TOTP, lockout, JWT
├── requirements.txt
├── README.md
└── frontend/
    └── index.html
```

## Author

Shrish Arunesh: [Portfolio](https://shashquash.github.io/portfolio) · [GitHub](https://github.com/ShashQuash)