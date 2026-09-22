import requests


class SecurityHeadersScanner:

    def __init__(self, engine):
        self.engine = engine

    def scan(self, url):

        try:
            response = self.engine.get(
                url
            )

        except requests.RequestException as error:
            return {
                "error": str(error),
                "findings": []
            }

        headers = {
            key.lower(): value
            for key, value in response.headers.items()
        }

        findings = []

        # Content-Security-Policy
        if "content-security-policy" not in headers:
            findings.append({
                "type": "Missing Content-Security-Policy",
                "severity": "Medium",
                "evidence": (
                    "Content-Security-Policy header "
                    "was not found."
                )
            })

        # X-Content-Type-Options
        if "x-content-type-options" not in headers:
            findings.append({
                "type": "Missing X-Content-Type-Options",
                "severity": "Low",
                "evidence": (
                    "X-Content-Type-Options header "
                    "was not found."
                )
            })

        # X-Frame-Options
        if "x-frame-options" not in headers:
            findings.append({
                "type": "Missing X-Frame-Options",
                "severity": "Low",
                "evidence": (
                    "X-Frame-Options header "
                    "was not found."
                )
            })

        # Referrer-Policy
        if "referrer-policy" not in headers:
            findings.append({
                "type": "Missing Referrer-Policy",
                "severity": "Low",
                "evidence": (
                    "Referrer-Policy header "
                    "was not found."
                )
            })

        # HSTS
        if url.startswith("https://") and "strict-transport-security" not in headers:
            findings.append({
                "type": "Missing Strict-Transport-Security",
                "severity": "Low",
                "evidence": (
                    "Strict-Transport-Security header "
                    "was not found."
                )
            })

        return {
            "url": url,
            "status_code": response.status_code,
            "findings": findings
        }