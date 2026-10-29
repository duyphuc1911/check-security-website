import unittest
from unittest.mock import patch

import requests

from security_headers import audit_security_headers


class SecurityHeadersTests(unittest.TestCase):
    def response(self, url, headers=None):
        response = requests.Response()
        response.url = url
        response.status_code = 200
        response.headers.update(headers or {})
        response.cookies = requests.cookies.cookiejar_from_dict({})
        return response

    @patch("security_headers.requests.get")
    def test_reports_present_headers_and_secure_cookie_attributes(self, get):
        get.return_value = self.response(
            "https://example.test/",
            headers={
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "camera=()",
                "Set-Cookie": "session=redacted; Secure; HttpOnly; SameSite=Lax",
            },
        )

        results = audit_security_headers("https://example.test/")

        self.assertTrue(results)
        self.assertTrue(all(result["status"] == "PASS" for result in results))
        get.assert_called_once_with(
            "https://example.test/", timeout=10, allow_redirects=False
        )

    @patch("security_headers.requests.get")
    def test_warns_about_missing_headers_and_cookie_attributes(self, get):
        get.return_value = self.response(
            "https://example.test/",
            headers={"Set-Cookie": "session=redacted"},
        )

        results = audit_security_headers("https://example.test/")

        warnings = {result["check"] for result in results if result["status"] == "WARN"}
        self.assertIn("Content-Security-Policy", warnings)
        self.assertIn("Strict-Transport-Security", warnings)
        self.assertIn("Cookie Secure", warnings)
        self.assertIn("Cookie HttpOnly", warnings)
        self.assertIn("Cookie SameSite", warnings)

    @patch("security_headers.requests.get")
    def test_does_not_require_hsts_for_http_response(self, get):
        get.return_value = self.response("http://example.test/")

        results = audit_security_headers("http://example.test/")

        hsts = next(result for result in results if result["check"] == "Strict-Transport-Security")
        self.assertEqual(hsts["status"], "PASS")
        https = next(result for result in results if result["check"] == "HTTPS")
        self.assertEqual(https["status"], "WARN")


if __name__ == "__main__":
    unittest.main()
