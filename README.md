# Smartest Bug Hunter Pro

A more advanced OWASP-focused security detector application for scanning web targets, storing historical scan results, generating PDF reports, and reviewing findings in a dashboard.

## Features

- User authentication and role-based admin access
- Secure registration/login flow with session cookies
- Database-backed scan history
- OWASP Top 10 category insights dashboard
- Per-scan vulnerability detail pages
- PDF export for findings reports
- Docker deployment support
- SQLite database for local persistence

## Stack

- FastAPI
- SQLAlchemy
- SQLite
- Jinja2 templates
- ReportLab PDF generation
- JWT-based authentication
- Docker

## Quick start

### Local setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

Open http://localhost:8000

### Demo accounts

The app creates an initial admin account automatically on first run:

- Username: `admin`
- Password: `admin123`

### Docker

```bash
docker build -t smartest-bug-hunter .
docker run -p 8000:8000 smartest-bug-hunter
```

Or with Docker Compose:

```bash
docker-compose up --build
```

## Security notes

- This project is intended for legal authorized security testing.
- Only scan domains you own or are explicitly allowed to test.
- Do not use this against third-party systems without permission.
