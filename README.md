# 🛡️ Detectify v4 — Production SaaS Architecture

> Final Year Project · Cybersecurity & Web Development · Full Stack Production

---

## 🏗️ Architecture

```
Browser → Express Server → Threat Intelligence Pipeline
                              ├── Claude AI (NLP analysis)
                              ├── Google Safe Browsing API
                              ├── VirusTotal API
                              └── Local Pattern Engine
                         → MongoDB (scan history + users)
                         → JWT Auth (secure sessions)
```

---

## 📁 Project Structure

```
Detectify-v4/
├── server/
│   ├── index.js              ← Express + Helmet + all middleware
│   ├── config/env.js         ← Env variable validation
│   ├── middleware/
│   │   ├── auth.js           ← JWT verification
│   │   ├── sanitize.js       ← XSS + URL validation
│   │   └── errorHandler.js   ← Centralized error handling
│   ├── models/db.js          ← MongoDB User + Scan models
│   ├── routes/
│   │   ├── scan.js           ← /api/scan, /api/health, /api/stats
│   │   └── auth.js           ← /api/auth/register, login, me
│   ├── services/
│   │   └── threatIntelligence.js ← Unified AI + GSB + VT scoring
│   └── utils/logger.js       ← Winston structured logging
├── public/                   ← Frontend (unchanged)
├── tests/api.test.js         ← Jest + Supertest API tests
├── Dockerfile
├── docker-compose.yml
├── .env.example
└── package.json
```

---

## 🚀 Run Locally (3 steps)

```bash
# 1. Install
npm install

# 2. Setup env
cp .env.example .env
# Edit .env — paste your ANTHROPIC_API_KEY at minimum

# 3. Start
npm run dev        # development (auto-restart)
npm start          # production
```
Open → http://localhost:3000

---

## 🌐 Deploy to Render.com (Free)

1. Push to GitHub (`.env` is gitignored ✅)
2. Render → New Web Service → connect repo
3. Build command: `npm install`
4. Start command: `npm start`
5. Add env vars in Render dashboard
6. Done — live URL in 2 minutes!

## 🐳 Deploy with Docker

```bash
cp .env.example .env   # fill in your keys
docker-compose up -d   # starts app + MongoDB
```

---

## 🔒 Security Features (v4)

| Feature | How |
|---|---|
| Helmet security headers | XSS, clickjacking, CSP protection |
| Input sanitization | xss library strips all injections |
| Blocked URL schemes | javascript:, data:, file: rejected |
| JWT authentication | Signed tokens, bcrypt passwords |
| Rate limiting | Global 100/15min + Scan 20/10min |
| API key protection | Only in .env, never in frontend |
| Centralized error handling | No stack traces leaked to client |
| Structured logging | Winston — errors.log + combined.log |

---

## 🧠 Threat Intelligence Sources

| Source | Weight | Requires |
|---|---|---|
| Local Pattern Engine | 20% | Nothing |
| Claude AI | 30% | ANTHROPIC_API_KEY |
| Google Safe Browsing | 35% | GOOGLE_SAFE_BROWSING_KEY |
| VirusTotal | 30% | VIRUSTOTAL_KEY |

All sources are optional — app works with just local checks if no keys set.

---

## 🧪 Run Tests

```bash
npm test
```

---

## 🔑 API Endpoints

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | /api/scan | Optional | Scan a URL |
| GET | /api/health | None | Server health check |
| GET | /api/stats | Optional | Scan statistics |
| POST | /api/auth/register | None | Create account |
| POST | /api/auth/login | None | Login |
| GET | /api/auth/me | Required | Get current user |

---

*Detectify v4 · Production SaaS · Final Year Project*
