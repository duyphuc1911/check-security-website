"""Passive checks for common HTTP response security headers."""

from http.cookies import SimpleCookie

import requests


def audit_security_headers(url):
    """Return PASS/WARN records for headers visible in one HTTP response.

    This check does not submit attack payloads. It inspects only the response
    headers and cookies returned by the target URL.
    """
    response = requests.get(url, timeout=10, allow_redirects=False)
    headers = response.headers
    is_https = response.url.lower().startswith("https://")
    content_security_policy = headers.get("Content-Security-Policy", "")
    frame_ancestors_configured = "frame-ancestors" in content_security_policy.lower()

    results = [
        {
            "status": "PASS" if is_https else "WARN",
            "check": "HTTPS",
            "message": (
                "The response uses HTTPS."
                if is_https
                else "Use HTTPS to protect data in transit."
            ),
        },
        {
            "status": (
                "PASS"
                if not is_https or headers.get("Strict-Transport-Security")
                else "WARN"
            ),
            "check": "Strict-Transport-Security",
            "message": (
                "HSTS is present or does not apply to this HTTP response."
                if not is_https or headers.get("Strict-Transport-Security")
                else "Add Strict-Transport-Security to HTTPS responses."
            ),
        },
        {
            "status": "PASS" if content_security_policy else "WARN",
            "check": "Content-Security-Policy",
            "message": (
                "Content-Security-Policy is present."
                if content_security_policy
                else "Define a Content-Security-Policy suited to the application."
            ),
        },
        {
            "status": (
                "PASS"
                if headers.get("X-Content-Type-Options", "").lower() == "nosniff"
                else "WARN"
            ),
            "check": "X-Content-Type-Options",
            "message": (
                "The response disables MIME sniffing."
                if headers.get("X-Content-Type-Options", "").lower() == "nosniff"
                else "Set X-Content-Type-Options: nosniff."
            ),
        },
        {
            "status": (
                "PASS"
                if headers.get("X-Frame-Options")
                or frame_ancestors_configured
                else "WARN"
            ),
            "check": "Clickjacking protection",
            "message": (
                "X-Frame-Options or CSP frame-ancestors is present."
                if headers.get("X-Frame-Options") or frame_ancestors_configured
                else "Set X-Frame-Options or a CSP frame-ancestors directive."
            ),
        },
        {
            "status": "PASS" if headers.get("Referrer-Policy") else "WARN",
            "check": "Referrer-Policy",
            "message": (
                "Referrer-Policy is present."
                if headers.get("Referrer-Policy")
                else "Set a Referrer-Policy appropriate for the application."
            ),
        },
        {
            "status": "PASS" if headers.get("Permissions-Policy") else "WARN",
            "check": "Permissions-Policy",
            "message": (
                "Permissions-Policy is present."
                if headers.get("Permissions-Policy")
                else "Set a restrictive Permissions-Policy for unused features."
            ),
        },
    ]

    raw_headers = getattr(response.raw, "headers", None)
    if raw_headers is not None and hasattr(raw_headers, "getlist"):
        set_cookie_headers = raw_headers.getlist("Set-Cookie")
    else:
        set_cookie_header = headers.get("Set-Cookie")
        set_cookie_headers = [set_cookie_header] if set_cookie_header else []

    for set_cookie_header in set_cookie_headers:
        parsed_cookies = SimpleCookie()
        parsed_cookies.load(set_cookie_header)
        for cookie in parsed_cookies.values():
            cookie_attributes = (
                ("Secure", bool(cookie["secure"])),
                ("HttpOnly", bool(cookie["httponly"])),
                ("SameSite", bool(cookie["samesite"])),
            )
            for attribute, is_set in cookie_attributes:
                results.append(
                    {
                        "status": "PASS" if is_set else "WARN",
                        "check": "Cookie " + attribute,
                        "message": (
                            "A response cookie has the " + attribute + " attribute."
                            if is_set
                            else "A response cookie is missing the "
                            + attribute
                            + " attribute; confirm whether it is needed."
                        ),
                    }
                )

    return results
