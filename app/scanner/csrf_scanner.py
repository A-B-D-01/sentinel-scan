import requests
from urllib.parse import urljoin


class CSRFScanner:

    def __init__(self, engine):
        self.engine = engine

    def scan_form(self, form, page_url):

        method = form.get("method", "GET").upper()
        action = form.get("action", page_url)
        action_url = urljoin(page_url, action)
        inputs = form.get("inputs", [])

        if method not in ["POST", "PUT", "PATCH", "DELETE"]:
            return {
                "vulnerable": False,
                "reason": "Form does not use a state-changing HTTP method.",
                "findings": []
            }

        # Check SameSite cookies by requesting the page
        samesite_strict_lax_found = False
        try:
            response = self.engine.get(page_url)
            if 'set-cookie' in response.headers:
                cookie_header = response.headers.get('set-cookie', '').lower()
                if 'samesite=strict' in cookie_header or 'samesite=lax' in cookie_header:
                    samesite_strict_lax_found = True
        except requests.RequestException:
            pass

        csrf_names = {
            "csrf",
            "csrf_token",
            "csrftoken",
            "_csrf",
            "_csrf_token",
            "xsrf",
            "xsrf_token",
            "authenticity_token",
            "anti_csrf_token"
        }

        token_found = False
        token_value = ""

        for input_field in inputs:
            name = input_field.get("name", "")
            if not name:
                continue

            normalized_name = name.lower().strip()
            if normalized_name in csrf_names:
                token_found = True
                token_value = input_field.get("value", "")
                break

        findings = []

        if not token_found:
            confidence = "High" if not samesite_strict_lax_found else "Medium"
            evidence = "State-changing form does not contain a recognizable CSRF token field."
            if not samesite_strict_lax_found:
                evidence += " Additionally, no SameSite=Strict/Lax cookies were observed, increasing risk."
            
            findings.append({
                "type": "Potential CSRF",
                "severity": "Medium",
                "confidence": confidence,
                "url": action_url,
                "parameter": None,
                "evidence": evidence
            })
            
        elif not token_value or len(token_value.strip()) < 16:
            confidence = "Medium"
            evidence = "A CSRF token field was found, but its value is missing or structurally weak (too short)."
            
            findings.append({
                "type": "Potential CSRF",
                "severity": "Medium",
                "confidence": confidence,
                "url": action_url,
                "parameter": None,
                "evidence": evidence
            })

        if findings:
            return {
                "vulnerable": True,
                "url": action_url,
                "method": method,
                "evidence": findings[0]["evidence"],
                "findings": findings
            }

        return {
            "vulnerable": False,
            "url": action_url,
            "method": method,
            "evidence": "A strong CSRF token field was found.",
            "findings": []
        }