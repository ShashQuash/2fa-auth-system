# 2FA Authentication System 🔐

A secure Two Factor Authentication system built with FastAPI and TOTP, 
featuring Google Authenticator integration.

Built by Shrish Arunesh — CS student in Berlin passionate about cybersecurity and backend development. This project was built as a hands-on learning exercise to deeply understand authentication systems, security concepts and full stack development.

---

## 🛠️ Tech Stack

- **Python** — core language
- **FastAPI** — backend API framework
- **pyotp** — TOTP code generation and verification
- **qrcode** — QR code generation for Google Authenticator
- **bcrypt** — secure password hashing
- **JWT** — session authentication
- **HTML, CSS, JavaScript** — frontend

---

## 🔍 Features

- User registration with automatic secret key generation
- QR code generation — scan with Google Authenticator
- TOTP verification — 6 digit codes that change every 30 seconds
- Full 2FA login — password + TOTP code required
- JWT token issued only after both checks pass
- Protected dashboard accessible only with valid token
- Security symbol snowfall animation frontend

---

## 🔐 How 2FA Works

1. User registers → server generates unique secret key
2. Secret key converted to QR code
3. User scans QR code with Google Authenticator
4. Phone and server now share the same secret key
5. Every 30 seconds both generate the same 6 digit code independently
6. At login — user enters password + current 6 digit code
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

Shrish Arunesh

---

## 📚 Learning Journey

This project was built as part of my self-directed learning journey 
into cybersecurity and backend development. Before building this I had 
no prior experience with authentication systems or security concepts.

Through building this project I deeply studied and now understand:

- **Why passwords must never be stored as plain text** and how bcrypt 
  solves this by being intentionally slow
- **How TOTP works mathematically** — how a phone and server can 
  independently generate the same 6 digit code every 30 seconds 
  using just a shared secret key and the current time
- **Why 2FA is significantly more secure** than passwords alone — 
  separating "something you know" from "something you have"
- **How QR codes transfer secrets** — the scan is the only interaction 
  needed between the phone and server
- **JWT token flow** — how stateless authentication works without 
  the server needing to remember anything
- **Full stack deployment** — connecting a Python backend to a 
  JavaScript frontend across different hosting platforms

I used AI as a learning assistant throughout this project — to explain 
concepts deeply, guide my understanding, and help debug issues. Every 
concept was studied until I could explain it in my own words before 
moving forward. The goal was never to copy code but to genuinely 
understand what I was building and why.

I am currently expanding my skills in cybersecurity and backend 
development — building real projects slowly and deeply rather than 
rushing through tutorials.