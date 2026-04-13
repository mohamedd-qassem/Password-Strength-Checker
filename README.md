# 🔐 SecurePass — Password Security Toolkit
https://secureyourpassword.netlify.app/ 

An web application to raise awareness about password security.

## Features

| Task | Description |
|------|-------------|
| ⚡ Password Generator | Cryptographically random passwords with length control (8–64 chars) |
| 📊 Strength Checker | Real-time entropy-based scoring with character-type breakdown |
| 💀 Cracking Simulator | Dictionary attack + brute-force estimate with terminal animation |

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the app
python app.py

# 3. Open in browser
# http://127.0.0.1:5000
```

## Project Structure

```
securepass/
├── app.py              ← Flask backend (all API logic)
├── wordlist.txt        ← 260+ common/leaked passwords for dictionary attack
├── requirements.txt
└── templates/
    └── index.html      ← Single-page frontend (HTML + CSS + JS)
```

## API Endpoints

| Method | Endpoint | Body | Description |
|--------|----------|------|-------------|
| POST | `/api/generate` | `{"length": 16}` | Generate a strong password |
| POST | `/api/check` | `{"password": "..."}` | Analyze password strength |
| POST | `/api/crack` | `{"password": "..."}` | Run cracking simulation |

## Strength Logic (Entropy-Based)

- **Entropy** = `length × log₂(character_pool_size)`
- **Weak** 😡 : < 8 chars OR entropy < 40 bits
- **Medium** 😐 : entropy 40–60 bits OR < 3 character types
- **Strong** 💪 : entropy ≥ 60 bits AND 3+ character types

## Cracking Simulation Tiers

Simulated at 1 billion guesses/second (modern GPU):

| Result | Condition |
|--------|-----------|
| ❌ Instant | Found in common wordlist |
| ❌ Cracked | Weak password — seconds |
| ⚠️ At Risk | Medium strength |
| ✅ Secure | Strong / centuries+ |

