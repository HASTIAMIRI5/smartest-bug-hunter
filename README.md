# smartest-bug-hunter

A lightweight OWASP-focused web vulnerability detector built as a demo security assessment dashboard. This project helps visualize common issues like missing security headers, insecure cookies, unsafe forms, and obvious injection patterns in live targets.

## Features

- URL-based security scan
- OWASP-style findings by category
- Risk score and severity summaries
- Security headers and cookie analysis
- HTML form and HTTP behavior inspection
- Easy local dashboard for demos and learning

## Quick start

1. Create a virtual environment
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   ```

2. Install dependencies
   ```bash
   pip install -r requirements.txt
   ```

3. Run the app
   ```bash
   python app.py
   ```

4. Open the browser at
   ```text
   http://localhost:5000
   ```

## What it checks

- HTTPS enforcement
- Security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy)
- Cookie security flags (Secure, HttpOnly, SameSite)
- Form security issues (GET submission, password exposure, weak patterns)
- Input validation hints and injection signatures
- Server fingerprinting and debug exposure

## Important note

This project is intentionally designed for learning, demos, and safe local testing. It does not replace a full enterprise-grade web security program or a professional penetration test.
