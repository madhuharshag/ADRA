# AegisCyber AI - Production Cybersecurity Risk Analysis Application

A production-ready, modular web application for evaluating organizational cybersecurity posture, calculating precision risk scores (0–100), categorizing threat levels, generating AI-driven mitigation advice, and archiving assessment records in SQLite.

---

## Key Features

- **Rule-Based Risk Calculation Engine**: Evaluates 13 critical security controls (MFA, Firewalls, Endpoint Security, Backups, Password Policies, Employee Training, Cloud Providers, Email Security Gateways, and Incident History) to generate an objective 0–100 risk score and Threat Level (`Low`, `Medium`, `High`, `Critical`).
- **Modular AI Advisory Service**: Features an intelligent local advisory engine for tailored executive summaries and prioritized action items. Pre-built adapter architecture allows seamless drop-in integration with OpenAI API (`gpt-4o` or `gpt-3.5-turbo`) by setting an environment key.
- **SQLite Data Persistence**: Automatically initializes and manages `database/app.db` with safe parameterized SQL queries to prevent SQL injection.
- **Cybersecurity Dark Theme UI**: High-contrast, responsive interface using Vanilla CSS3 and Vanilla JavaScript (no heavy frontend frameworks required). Includes SVG animated score gauges, risk factor breakdown cards, and dynamic history logs.
- **Built-In Security & Rate Limiting**: Uses `Flask-Limiter` to mitigate denial-of-service (DoS) and brute-force attempts, `python-dotenv` for configuration separation, and comprehensive server-side input validation.

---

## Project Structure

```
adra/
│
├── server.py             # Flask application entry point, error handlers & logger
├── routes.py             # HTTP routes & endpoint rate limiting rules
├── controller.py         # Request validation & business logic orchestrator
├── db_service.py         # SQLite connection manager & SQL queries
├── ai_service.py         # Modular AI Advisory service (Local Heuristic + OpenAI adapter)
├── risk_service.py       # Deterministic cybersecurity rule-based scoring engine
├── requirements.txt      # Python package dependencies
├── README.md             # Project documentation & usage manual
├── .env.example          # Environment variable template
├── .gitignore            # Git exclusion rules
│
├── templates/
│   └── index.html        # Single-page landing & dynamic dashboard template
│
├── static/
│   ├── style.css         # Modern dark cybersecurity stylesheet
│   └── script.js         # Vanilla JS Fetch API engine & dynamic renderers
│
└── database/
    └── app.db            # SQLite database file (Auto-created on first run)
```

---

## Installation & Setup

### Prerequisites

- **Python 3.8+**
- `pip` (Python package manager)

### 1. Install Dependencies

Install required dependencies listed in `requirements.txt`:

```bash
python3 -m pip install -r requirements.txt
```

### 2. Configure Environment Variables

Copy `.env.example` to `.env` to customize settings:

```bash
cp .env.example .env
```

Default configuration in `.env`:
```env
FLASK_ENV=development
SECRET_KEY=cyber_security_super_secret_key_change_in_production_2026
OPENAI_API_KEY=your_openai_api_key_here
DATABASE_URL=sqlite:///database/app.db
PORT=5000
HOST=0.0.0.0
```

*Note: If `OPENAI_API_KEY` is left as placeholder or empty, the system automatically uses the high-performance local AI Advisory engine.*

---

## Running the Application

Execute the server launcher:

```bash
python3 server.py
```

The web application will initialize the database at `database/app.db` and start serving at:
[http://localhost:5000](http://localhost:5000)

---

## API Specification

### `POST /risk`
Processes a new cybersecurity risk assessment.

- **Rate Limit**: 10 requests per minute
- **Request Headers**: `Content-Type: application/json`
- **Request Body**:
```json
{
  "company_name": "Acme Cyber Systems",
  "industry": "Finance & Banking",
  "employees": 250,
  "uses_mfa": "No",
  "firewall_enabled": "Yes",
  "antivirus_installed": "Yes",
  "backup_strategy": "Infrequent",
  "password_policy": "Weak",
  "public_wifi_usage": "Yes",
  "employee_training": "No",
  "cloud_provider": "AWS",
  "email_security": "Basic",
  "previous_incidents": 2
}
```

- **Success Response (201 Created)**:
```json
{
  "success": true,
  "assessment_id": 1,
  "company_name": "Acme Cyber Systems",
  "industry": "Finance & Banking",
  "employees": 250,
  "risk_score": 65,
  "risk_level": "High",
  "risk_breakdown": [ ... ],
  "ai_explanation": "...",
  "recommendations": [ ... ]
}
```

### `GET /risk`
Retrieves recent assessment records saved in SQLite.

- **Rate Limit**: 30 requests per minute
- **Query Parameter**: `limit` (default: 20)

### `GET /risk/<id>`
Retrieves full audit log details for a specific assessment record ID.

---

## Security Practices Applied

1. **Rate Limiting**: `Flask-Limiter` prevents API abuse.
2. **Parameterized Queries**: `db_service.py` uses `?` bindings for all SQL queries to eliminate SQL injection risks.
3. **Input Sanitization**: `controller.py` strictly validates and sanitizes all input fields before processing.
4. **Environment Isolation**: Secrets and configuration parameters are loaded via `python-dotenv` and never committed to code repository.
5. **Clean Separation of Concerns**: Strict architecture separating routes, controllers, services, database access, and frontend presentations.

---

## Swapping Local AI with OpenAI API

To switch the AI Advisor from local heuristics to OpenAI:
1. Set `OPENAI_API_KEY=sk-...` in your `.env` file.
2. Install `openai` package (`pip install openai`).
3. Restart `server.py`. The application automatically detects the valid key in `ai_service.py` and switches providers seamlessly!

---

## Future Enhancements

- **PDF Audit Report Export**: Generate downloadable executive security assessment PDFs.
- **Enterprise SSO / OAuth2**: Authenticate security officers via Okta or Microsoft Entra ID.
- **Benchmarking Analytics**: Compare company risk metrics against industry peers.
