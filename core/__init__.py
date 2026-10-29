from __future__ import annotations

import re
from typing import Any, Dict, List

import requests
from urllib.parse import urlparse

SECURITY_HEADERS = [
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "strict-transport-security",
]


def make_finding(category: str, severity: str, title: str, description: str, remediation: str, evidence: str = "") -> Dict[str, Any]:
    return {
        "category": category,
        "severity": severity,
        "title": title,
        "description": description,
        "remediation": remediation,
        "evidence": evidence,
    }


def detect_target(target_url: str) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []

    try:
        response = requests.get(target_url, timeout=15, allow_redirects=True)
        page_text = response.text.lower()
        headers = {k.lower(): v for k, v in response.headers.items()}
        status_code = response.status_code
        base_domain = urlparse(target_url).netloc.lower()

        if not response.ok:
            findings.append(
                make_finding(
                    "Reconnaissance",
                    "info",
                    "HTTP response status indicates an issue",
                    f"The target responded with status {status_code}.",
                    "Review server configuration and application errors to confirm expected behavior.",
                    f"Status code: {status_code}",
                )
            )

        missing_headers = [h for h in SECURITY_HEADERS if h not in headers]
        if missing_headers:
            findings.append(
                make_finding(
                    "Headers",
                    "medium",
                    "Missing security headers",
                    "The application is missing one or more important HTTP security headers.",
                    "Add CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, HSTS, and Permissions-Policy headers to harden responses.",
                    ", ".join(missing_headers),
                )
            )

        if "set-cookie" in headers:
            cookie_header = headers.get("set-cookie", "")
            if "secure" not in cookie_header.lower() or "httponly" not in cookie_header.lower():
                findings.append(
                    make_finding(
                        "Cookies",
                        "medium",
                        "Insecure cookie configuration",
                        "Cookies are being set without Secure or HttpOnly attributes.",
                        "Set Secure, HttpOnly, and ideally SameSite=Lax or Strict on all sensitive cookies.",
                        cookie_header,
                    )
                )

        if any(pattern in page_text for pattern in ["<script", "javascript:", "onerror=", "onmouseover=", "eval(", "innerhtml"]):
            findings.append(
                make_finding(
                    "XSS",
                    "high",
                    "Potential cross-site scripting vectors",
                    "The rendered page contains common client-side injection markers that could be exploited by an attacker.",
                    "Output encode user-controlled content, use a strict CSP, and sanitize any dynamic HTML insertion.",
                    "Pattern matched in HTML or JavaScript output.",
                )
            )

        if any(pattern in page_text for pattern in ["union select", "or 1=1", "sleep(", "drop table", ";--", "admin' --"]):
            findings.append(
                make_finding(
                    "Injection",
                    "critical",
                    "Potential SQL injection indicators",
                    "The application appears to include unsafe SQL patterns or database query behavior in rendered output.",
                    "Use parameterized queries, ORM abstraction, and validation on all inputs that reach the database.",
                    "One or more suspicious SQL patterns were detected.",
                )
            )

        forms = re.findall(r"<form[^>]*>", response.text, flags=re.IGNORECASE)
        if forms:
            csrf_token = any("csrf" in token.lower() or "csrf_token" in token.lower() for token in response.text.lower().split())
            if not csrf_token:
                findings.append(
                    make_finding(
                        "CSRF",
                        "medium",
                        "Possible missing CSRF protection",
                        "A form was detected without obvious CSRF token enforcement.",
                        "Validate anti-CSRF tokens on state-changing requests and use SameSite cookies where appropriate.",
                        f"Detected {len(forms)} forms.",
                    )
                )

        if response.history or response.url != target_url:
            findings.append(
                make_finding(
                    "Redirect",
                    "medium",
                    "Open redirect or redirect chaining detected",
                    "The request was redirected, which may create open redirect or phishing opportunities.",
                    "Restrict redirect targets to trusted domains and validate all redirect destinations before sending a redirect response.",
                    f"Final URL: {response.url}",
                )
            )

        if "server" in headers:
            server_value = headers.get("server", "")
            if server_value and any(v in server_value.lower() for v in ["apache", "nginx", "iis", "gunicorn"]):
                findings.append(
                    make_finding(
                        "Misconfiguration",
                        "low",
                        "Server fingerprinting is exposed",
                        "The server software is disclosed in HTTP headers, enabling reconnaissance for attackers.",
                        "Reduce unnecessary header exposure and ensure product details do not leak through response metadata.",
                        f"Server header: {server_value}",
                    )
                )

        if re.search(r"(?:redirect|next|return|url)\s*[:=]\s*['\"]?https?://", page_text):
            findings.append(
                make_finding(
                    "Open redirect",
                    "medium",
                    "URL-based redirect parameter may be unsafe",
                    "User-controlled redirect parameters were found in the page or application output.",
                    "Allow only relative redirects or validate destinations against a whitelist of trusted domains.",
                    "Redirect parameter pattern detected.",
                )
            )

    except requests.RequestException as exc:
        findings.append(
            make_finding(
                "Connectivity",
                "info",
                "Unable to reach the target",
                f"The scanner could not connect to {target_url}.",
                "Verify the URL, ensure the service is reachable, and confirm that network or firewall rules allow the request.",
                str(exc),
            )
        )

    deduped: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for item in findings:
        key = (item["category"], item["title"])
        if key not in seen:
            seen.add(key)
            deduped.append(item)

    severity_ranking = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    highest_severity = "info"
    if deduped:
        highest_severity = max(deduped, key=lambda x: severity_ranking.get(x["severity"], 0))["severity"]

    return {
        "status": "ok",
        "target": target_url,
        "summary": {
            "total_findings": len(deduped),
            "highest_severity": highest_severity,
            "domain": base_domain if "base_domain" in locals() else urlparse(target_url).netloc,
        },
        "findings": deduped,
    }

