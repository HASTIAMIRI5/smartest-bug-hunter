# Smartest Bug Hunter

A lightweight OWASP-focused security audit app built to detect common web vulnerabilities such as XSS, SQL injection patterns, insecure headers, missing CSRF protection, and weak security posture.

## Features

- Web UI for entering a target URL
- Automatic OWASP-inspired checks
- Severity scoring and categorization
- Security recommendation guidance
- Fast local deployment using FastAPI

## Quick start

1. Create a virtual environment
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

2. Install dependencies
   ```bash
   pip install -r requirements.txt
   ```

3. Run the app
   ```bash
   uvicorn app:app --host 0.0.0.0 --port 8000 --reload
   ```

4. Open:
   ```text
   http://localhost:8000
   ```

## Example checks performed

- Missing security headers
- Cross-site scripting patterns
- SQL injection indicators
- Open redirect opportunities
- Missing CSRF protections
- Insecure cookie settings
- Information leakage in HTTP responses

## Notes

This is a demo security scanner for educational and testing purposes only. Only test targets you own or are explicitly authorized to audit.
