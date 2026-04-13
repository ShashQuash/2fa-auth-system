# 2FA Authentication System 🔐

A two-factor authentication system built with FastAPI, implementing TOTP-based login, bcrypt password hashing, and JWT session management — integrated with Google Authenticator.

Built by Shrish Arunesh — CS student in Berlin, focused on cybersecurity and backend development.

---

## 🌐 Live Demo

| | Link |
|---|---|
| **Frontend** | [Click to visit](https://shashquash.github.io/2fa-auth-system/frontend) |
| **API Docs** | [Click to visit](https://twofa-auth-system.onrender.com/docs) |

---

## 🛠️ Tech Stack

- **Python** - core language
- **FastAPI** - backend API framework
- **pyotp** - TOTP code generation and verification
- **qrcode** - QR code generation for Google Authenticator
- **bcrypt** - secure password hashing
- **JWT** - session authentication
- **HTML, CSS, JavaScript** - frontend

---

## 🔍 Features

- User registration with automatic secret key generation
- QR code generation — scan with Google Authenticator
- TOTP verification — 6-digit codes that rotate every 30 seconds
- Full 2FA login — password + TOTP code both required
- JWT token issued only after both checks pass
- Protected dashboard accessible only with valid token

---

## 🔐 How 2FA Works

1. User registers → server generates a unique secret key
2. Secret key is converted to a QR code
3. User scans QR code with Google Authenticator
4. Phone and server now share the same secret key
5. Every 30 seconds, both independently generate the same 6-digit code
6. At login — user enters password + current 6-digit code
7. Server verifies both → issues JWT token

---

## 📡 API Endpoints

| Method | Endpoint      | Description                | Auth Required |
|--------|---------------|----------------------------|---------------|
| GET    | `/`           | API status                 | No            |
| POST   | `/register`   | Register + get QR code     | No            |
| POST   | `/verify-2fa` | Verify TOTP setup          | No            |
| POST   | `/login`      | Login with password + TOTP | No            |
| GET    | `/dashboard`  | Protected dashboard        | Yes           |

---

## 👨‍💻 Author

Shrish Arunesh · [Portfolio](https://shashquash.github.io/portfolio) · [GitHub](https://github.com/ShashQuash)