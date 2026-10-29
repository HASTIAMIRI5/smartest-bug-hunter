from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "scan_history.db")
DB_PATH = os.path.abspath(DB_PATH)


def _get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_history_table() -> None:
    conn = _get_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            summary TEXT NOT NULL,
            findings_json TEXT NOT NULL,
            categories_json TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.commit()
    conn.close()


def _add_finding(findings: List[Dict[str, str]], category: str, title: str, severity: str, description: str, evidence: str, recommendation: str) -> None:
    findings.append(
        {
            "category": category,
            "title": title,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "recommendation": recommendation,
        }
    )


def _severity_weight(severity: str) -> int:
    return {"critical": 5, "high": 4, "medium": 3, "low": 1}.get((severity or "low").lower(), 1)


def _safe_text(value: Any) -> str:
    text = str(value or "").strip()
    return text[:250]


def _normalize_target(target: str) -> str:
    candidate = (target or "").strip()
    if not candidate:
        return ""
    if not candidate.startswith(("http://", "https://")):
        candidate = "https://" + candidate
    return candidate


def _extract_forms(html: str) -> List[str]:
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        method = (form.get("method") or "get").upper()
        action = form.get("action") or ""
        forms.append(f"method={method}; action={action}")
    return forms


def auth_simulation(target: str, username: str = "", password: str = "") -> Dict[str, Any]:
    candidate = _normalize_target(target)
    result: Dict[str, Any] = {
        "target": candidate,
        "username": username or "demo-user",
        "password_provided": bool(password),
        "login_form_found": False,
        "risk_level": "Info",
        "checks": [],
        "summary": "No login form detected.",
    }

    try:
        response = requests.get(candidate, timeout=12, allow_redirects=True)
    except requests.RequestException as exc:  # pragma: no cover - network failure path
        result["risk_level"] = "Error"
        result["summary"] = f"Authentication simulation failed: {exc}"
        return result

    html = response.text.lower()
    soup = BeautifulSoup(response.text, "html.parser")
    login_indicators = ["login", "signin", "sign in", "auth", "password", "remember me"]
    login_page = any(token in html for token in login_indicators)
    password_input = soup.find("input", {"type": "password"}) is not None
    forms = _extract_forms(response.text)

    result["login_form_found"] = bool(password_input or forms or login_page)
    result["checks"] = [
        f"Password input present: {bool(password_input)}",
        f"Login indicators detected: {login_page}",
        f"Forms found: {len(forms)}",
    ]

    if not result["login_form_found"]:
        result["summary"] = "No obvious authentication flow was found on the target page."
        result["risk_level"] = "Low"
        return result

    if not password:
        result["summary"] = "A login or credential gate appears to exist, but no password was supplied for the simulation."
        result["risk_level"] = "Moderate"
        return result

    if login_page and password_input:
        result["summary"] = "The target appears to expose a credential-based login flow and handles form-based authentication in a standard way."
        result["risk_level"] = "Moderate"
        if "https" not in candidate:
            result["risk_level"] = "High"
            result["summary"] = "The target appears to expose a login form over an insecure channel."
        return result

    result["summary"] = "The target has a login-like interface but the authentication flow should be validated manually."
    result["risk_level"] = "Moderate"
    return result


def scan_target(target: str, username: str = "", password: str = "") -> Dict[str, Any]:
    ensure_history_table()
    candidate = _normalize_target(target)
    if not candidate:
        return {
            "target": "",
            "score": 0,
            "risk_level": "Error",
            "summary": "Please provide a valid target URL.",
            "findings": [],
            "categories": [],
        }

    findings: List[Dict[str, str]] = []

    try:
        response = requests.get(candidate, timeout=12, allow_redirects=True)
    except requests.RequestException as exc:
        return {
            "target": candidate,
            "score": 0,
            "risk_level": "Error",
            "summary": f"The scan could not reach the target: {exc}",
            "findings": [],
            "categories": [],
        }

    headers = response.headers
    html = response.text
    soup = BeautifulSoup(html, "html.parser")
    parsed = urlparse(candidate)

    # A01 Broken Access Control
    query_string = parsed.query.lower()
    if any(token in query_string for token in ["admin", "debug", "token", "password", "secret", "session", "role"]):
        _add_finding(
            findings,
            "A01: Broken Access Control",
            "Sensitive parameters visible in the URL",
            "medium",
            "Sensitive values are exposed in the query string, making them susceptible to leakage in logs, history, and referrer headers.",
            f"Query string contains: {query_string[:200]}",
            "Move sensitive values into POST bodies or server-side sessions and avoid exposing them in URLs.",
        )

    # A02 Cryptographic Failures
    if parsed.scheme != "https":
        _add_finding(
            findings,
            "A02: Cryptographic Failures",
            "Target is not enforcing HTTPS",
            "high",
            "The application is serving content over plain HTTP, which allows interception and tampering of traffic.",
            f"URL scheme detected: {parsed.scheme}",
            "Redirect all requests to HTTPS and enforce HSTS for the site and subdomains.",
        )

    if "strict-transport-security" not in {k.lower(): v for k, v in headers.items()}:
        _add_finding(
            findings,
            "A02: Cryptographic Failures",
            "HSTS header is missing",
            "medium",
            "No Strict-Transport-Security policy is present to protect the user against downgrade and MITM attacks.",
            "Missing Strict-Transport-Security header",
            "Set a strong HSTS policy such as max-age=31536000; includeSubDomains.",
        )

    # A03 Injection
    injection_markers = [
        ("<script>", "Script injection pattern"),
        ("eval(", "Dynamic code execution pattern"),
        ("union select", "SQL injection keyword"),
        ("or 1=1", "Boolean injection pattern"),
        ("javascript:", "Unsafe protocol usage"),
    ]
    for needle, label in injection_markers:
        if needle.lower() in html.lower():
            _add_finding(
                findings,
                "A03: Injection",
                "Suspicious injection or unsafe sink pattern detected",
                "high",
                "The response contains a pattern commonly associated with unsafe data handling or injection testing.",
                f"Matched pattern: {label} ({needle})",
                "Sanitize user input, avoid unsafe string concatenation, and encode output before rendering in HTML, JavaScript, or SQL.",
            )

    # A04 Insecure Design
    if response.status_code >= 500:
        _add_finding(
            findings,
            "A04: Insecure Design",
            "Server-side error handling appears to expose internal details",
            "medium",
            "The application is returning a server error that may reveal application internals or unsafe diagnostics.",
            f"HTTP status code: {response.status_code}",
            "Use centralized, sanitized error handling and avoid exposing stack traces or internal details to users.",
        )

    # A05 Security Misconfiguration
    missing_headers = [
        ("content-security-policy", "Content-Security-Policy"),
        ("x-frame-options", "X-Frame-Options"),
        ("x-content-type-options", "X-Content-Type-Options"),
        ("referrer-policy", "Referrer-Policy"),
        ("permissions-policy", "Permissions-Policy"),
    ]
    header_map = {k.lower(): v for k, v in headers.items()}
    for key, label in missing_headers:
        if key not in header_map:
            _add_finding(
                findings,
                "A05: Security Misconfiguration",
                f"Missing {label} header",
                "medium",
                f"The server is not sending the recommended {label} header, which weakens browser-side protections.",
                f"Missing header: {label}",
                f"Add {label} with a restrictive but valid policy suitable for the application.",
            )

    if "x-powered-by" in header_map or "server" in header_map:
        _add_finding(
            findings,
            "A05: Security Misconfiguration",
            "Framework and server information is exposed",
            "low",
            "The response leaks framework and environment information that can help attackers target known vulnerabilities.",
            f"Headers revealed: {header_map.get('x-powered-by', 'N/A')} / {header_map.get('server', 'N/A')}",
            "Remove or normalize framework fingerprinting headers in production deployments.",
        )

    # A06 Vulnerable and Outdated Components
    tech_hints = ["jquery", "bootstrap", "angular", "react", "vue", "apache", "nginx", "php", "asp.net"]
    lowercase_html = html.lower()
    component_hits = [tool for tool in tech_hints if tool in lowercase_html]
    if component_hits:
        _add_finding(
            findings,
            "A06: Vulnerable and Outdated Components",
            "Detected frontend or server components with potential update risk",
            "medium",
            "The page includes framework or server component references that may require version review and patching.",
            f"Detected references: {', '.join(component_hits[:5])}",
            "Review framework versions, apply patches, and keep dependency inventories up to date.",
        )

    # A07 Identification and Authentication Failures
    if soup.find("input", {"type": "password"}):
        _add_finding(
            findings,
            "A07: Identification and Authentication Failures",
            "Password form is present without strong security evidence",
            "medium",
            "The application contains a password input, but no clear evidence of hardened authentication controls was detected.",
            "Detected password field in HTML form",
            "Review authentication flows, enable MFA, and enforce lockout, secure session handling, and strong password policies.",
        )

    cookies = response.cookies
    for cookie in cookies:
        weak_flags = []
        if not cookie.secure:
            weak_flags.append("Secure")
        if not cookie.has_nonstandard_attr("HttpOnly"):
            weak_flags.append("HttpOnly")
        if cookie._rest.get("SameSite") is None:
            weak_flags.append("SameSite")
        if weak_flags:
            _add_finding(
                findings,
                "A07: Identification and Authentication Failures",
                "Session cookie is missing protective attributes",
                "medium",
                f"The cookie '{cookie.name}' does not include the recommended protection flags: {', '.join(weak_flags)}.",
                f"Cookie flags for '{cookie.name}': {', '.join(weak_flags)}",
                "Set Secure, HttpOnly, and SameSite attributes on session and auth cookies.",
            )

    # A08 Software and Data Integrity Failures
    external_sources = []
    for tag in soup.find_all(["script", "img", "link", "iframe"]):
        src = tag.get("src") or tag.get("href") or ""
        if src.startswith("http") and not src.startswith(candidate):
            external_sources.append(src)
    if external_sources:
        _add_finding(
            findings,
            "A08: Software and Data Integrity Failures",
            "Application loads resources from external origins",
            "low",
            "The page includes third-party resources that may be tampered with or abused if not tightly controlled.",
            f"External resources: {', '.join(external_sources[:3])}",
            "Review all third-party resources, prefer integrity hashes, and constrain trusted external origins.",
        )

    # A09 Security Logging and Monitoring Failures
    if "debug" in html.lower() or "trace" in html.lower():
        _add_finding(
            findings,
            "A09: Security Logging and Monitoring Failures",
            "Debug or diagnostic details may be exposed",
            "medium",
            "The page contains debug or trace-related content that may leak sensitive operational information.",
            "Detected debug or tracing text in response body",
            "Disable debug output in production and make sure sensitive operational details are not exposed to users.",
        )

    # A10 SSRF
    for tag in soup.find_all(["a", "form", "script", "img", "iframe"]):
        source = tag.get("src") or tag.get("href") or ""
        if source.startswith("http://") and ("localhost" in source.lower() or "127.0.0.1" in source.lower() or "internal" in source.lower()):
            _add_finding(
                findings,
                "A10: Server-Side Request Forgery",
                "Potential internal endpoint reference detected",
                "medium",
                "The page references a local or internal URL, which may indicate a dangerous SSRF or network trust issue if used by backend code.",
                f"Suspicious URL: {source}",
                "Validate outbound URLs against allowlists and restrict server-side requests to trusted destinations only.",
            )

    deduped: List[Dict[str, str]] = []
    seen: set = set()
    for item in findings:
        key = (item["category"], item["title"], item["evidence"])
        if key not in seen:
            deduped.append(item)
            seen.add(key)

    total_weight = sum(_severity_weight(item["severity"]) for item in deduped)
    score = max(0, min(100, 100 - (total_weight * 7)))
    if score >= 85:
        risk_level = "Low"
    elif score >= 65:
        risk_level = "Moderate"
    elif score >= 40:
        risk_level = "High"
    else:
        risk_level = "Critical"

    summary = (
        f"Detected {len(deduped)} OWASP-relevant issue(s). "
        f"Overall risk rating: {risk_level}."
    )

    result = {
        "target": candidate,
        "score": int(score),
        "risk_level": risk_level,
        "summary": summary,
        "findings": deduped,
        "categories": sorted({finding["category"] for finding in deduped}),
    }

    save_scan_result(result)
    return result


def save_scan_result(result: Dict[str, Any]) -> None:
    ensure_history_table()
    conn = _get_connection()
    conn.execute(
        """
        INSERT INTO scan_history (target, score, risk_level, summary, findings_json, categories_json)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            result.get("target", ""),
            int(result.get("score", 0)),
            result.get("risk_level", "Info"),
            result.get("summary", ""),
            json.dumps(result.get("findings", [])),
            json.dumps(result.get("categories", [])),
        ),
    )
    conn.commit()
    conn.close()


def get_history(limit: int = 10) -> List[Dict[str, Any]]:
    ensure_history_table()
    conn = _get_connection()
    rows = conn.execute(
        """
        SELECT target, score, risk_level, summary, findings_json, categories_json, created_at
        FROM scan_history
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    conn.close()
    history = []
    for row in rows:
        history.append(
            {
                "target": row["target"],
                "score": row["score"],
                "risk_level": row["risk_level"],
                "summary": row["summary"],
                "findings": json.loads(row["findings_json"] or "[]"),
                "categories": json.loads(row["categories_json"] or "[]"),
                "created_at": row["created_at"],
            }
        )
    return history


def export_history(format_name: str = "json") -> str:
    ensure_history_table()
    history = get_history(limit=100)
    if format_name.lower() == "csv":
        output = []
        output.append("target,score,risk_level,summary,created_at")
        for item in history:
            target = item["target"].replace('"', '""')
            summary = item["summary"].replace('"', '""')
            output.append(f'"{target}",{item["score"]},"{item["risk_level"]}","{summary}","{item["created_at"]}"')
        return "\n".join(output) + "\n"
    return json.dumps({"history": history}, indent=2)


__all__ = ["scan_target", "auth_simulation", "get_history", "export_history"]
