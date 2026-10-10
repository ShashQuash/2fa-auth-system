# Two-Factor Authentication System

A FastAPI backend that adds TOTP-based 2FA on top of password login, the same kind Google Authenticator and Authy use. Password plus a rotating 6-digit code, with the brute-force and replay defenses that a second factor actually needs to be worth having.

Built by Shrish Arunesh, a CS student in Berlin working with backend and security concepts.

## Live Demo

Frontend: [shashquash.github.io/2fa-auth-system/frontend](https://shashquash.github.io/2fa-auth-system/frontend)
API docs: [twofa-auth-system.onrender.com/docs](https://twofa-auth-system.onrender.com/docs)

Heads up: the backend sleeps on a free tier, so the first request after a quiet spell can take around 50 seconds to wake up. Give it a second and retry.

## Stack

Python, FastAPI, bcrypt (via passlib), pyotp for TOTP, qrcode for enrollment, PyJWT for tokens, SlowAPI for rate limiting. Plain HTML/CSS/JS frontend.

## How the flow works

1. Register with a username and password. The server creates a TOTP secret and hands back a QR code.
2. Scan the QR with any authenticator app, or type the secret in manually if you can't scan.
3. Enter the 6-digit code once to confirm the app and server are in sync. That activates 2FA.
4. From then on, login needs all three: username, password, and the current code.

## What it does

**Passwords** are hashed with bcrypt before storage. The plaintext is never saved. (The functions are named `hash_password` / `verify_password` on purpose. bcrypt hashes, it doesn't encrypt, and the difference matters.)

**Password length is bounded at both ends**, and the upper bound is the interesting one. bcrypt only reads the first 72 *bytes* and silently ignores the rest, so without a cap a long password looks accepted but is only partly verified, and anything sharing those first 72 bytes authenticates just as well. Registration rejects over 72 bytes and under 8 characters. The cap applies at login too, so a long password can't match its own truncated prefix. It counts bytes rather than characters, because one euro sign is three bytes and a character count would let it slip through.

**TOTP enrollment** generates a per-user secret and a scannable QR code. The secret is shown once during setup for manual entry, which is exactly how authenticator apps expect it. After that it's never sent back.

**Login** checks the password first, then the TOTP code, and only issues a JWT (30-minute expiry) when both pass.

**Rate limiting** caps login and verification at 5 requests per minute per IP, and registration at 10. A 6-digit code is only a million combinations, so the limit on the code endpoints is what makes brute force impractical. Registration needs one too: users live in an in-memory dictionary, so an unthrottled register endpoint is a way to grow it until the process runs out of memory.

**Account lockout** triggers after 5 failed attempts and lasts 15 minutes, then clears itself. No permanent locks from a few typos. It covers verification as well as login. It originally only covered login, which left `/verify-2fa` sitting behind nothing but a per-IP limit, and a caller who guessed the code there could flip an account to verified without ever knowing its password.

**Replay protection** rejects a code that was just used. TOTP codes stay valid for their full 30-second window, so without this an attacker who sniffs one code could reuse it. The server remembers the last accepted code and refuses a repeat. Verification records the code too, not just login. It didn't originally, which meant the code you type to *activate* 2FA could be replayed straight into login inside the same 30 seconds. Small window, but it was a hole in a defence this README already claimed to have.

**No username leaks.** Failed logins and failed verifications return the same generic error whether the account exists or not, and a login for a missing user still runs a throwaway hash check so you can't tell real usernames apart by timing. The one exception is after a correct password: an unverified account is told to finish 2FA setup, but that only ever reaches someone who already has the right password.

## Endpoints

| Method | Endpoint | What it does | Auth | Rate limit |
|--------|----------|--------------|------|------------|
| GET | `/` | Health check | No | none |
| POST | `/register` | Create an account, get a QR code (201) | No | 10/min per IP |
| POST | `/verify-2fa` | Confirm the first code, activate 2FA | No | 5/min per IP |
| POST | `/login` | Password + TOTP, get a JWT (200) | No | 5/min per IP |
| GET | `/dashboard` | Example protected route | Yes | none |

Errors you'll see: `401` for bad credentials, a bad code, a reused code, or a bad token; `403` if the password is right but 2FA isn't set up yet; `409` if the username is taken; `429` if the account is locked or you've hit the rate limit; `422` for a malformed body or a password outside the length bounds.

## What it doesn't do (yet)

Being upfront about the gaps:

- The TOTP secret is stored as-is in memory. For a demo that's fine, but a real build would encrypt it at rest with a key kept outside the database.
- Users and lockout state live in memory, so they reset on restart and won't work across multiple workers. Production would use a database plus something like Redis.
- The lockout is keyed on username, so someone could deliberately lock a known account for 15 minutes. The per-IP rate limit softens it; the fuller fix is keying on IP plus username.
- `failed_attempts` is keyed on whatever username the caller sends. Misses on usernames that don't exist aren't counted, specifically so the dictionary can't be grown by a stranger, but real accounts under attack still accumulate entries.
- Replay protection remembers only the last accepted code per user. That covers the realistic case, but a proper implementation would track every code consumed within the current window.
- CORS is still `allow_origins=["*"]`. Low risk here because credentials aren't allowed and auth is a Bearer header rather than a cookie, but it should be pinned to the known frontend origin.
- No backup codes or device recovery. Lose the authenticator, lose access. A real product needs a recovery path.
- The frontend keeps the JWT in `localStorage`, which is exposed to XSS. An HttpOnly cookie would be safer.

### Dependency notes

- JWTs moved from `python-jose` to `PyJWT`. python-jose is effectively unmaintained, and it pulls in `ecdsa`, which carries CVE-2024-23342, a timing attack on P-256. That advisory has no fix and the ecdsa maintainers consider side-channel attacks out of scope, so `pip-audit` failed CI on every push with nothing to upgrade to. This service signs with HS256, which is HMAC and never touches elliptic curves, so the vulnerability was never reachable from this code. Carrying a permanently red build for an unreachable advisory wasn't worth it. PyJWT has no dependencies at all and removed eight packages from the tree.
- `passlib` is unmaintained. `bcrypt` is pinned to `4.0.1` because passlib runs an internal self-test on a password longer than 72 bytes, and bcrypt 4.1 and later raise on that instead of truncating, which breaks every hash call. The real fix is dropping passlib for the `bcrypt` library directly.
- Everything in `requirements.txt` is version pinned, transitive dependencies included, so a deploy installs what was actually tested.

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
$env:JWT_SECRET = "<your-long-random-secret>"   # PowerShell
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

Shrish Arunesh