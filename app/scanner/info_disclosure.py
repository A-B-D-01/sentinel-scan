from urllib.parse import urlparse, urljoin
import requests

class InfoDisclosureScanner:
    def __init__(self, engine):
        self.engine = engine
        self.sensitive_files = {
            "/.env": ["db_password", "secret_key"],
            "/.git/config": ["[core]"],
            "/robots.txt": ["user-agent:", "disallow:"],
            "/server-status": ["apache server status"]
        }

    def scan(self, target_url):
        findings = []
        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for path, signatures in self.sensitive_files.items():
            test_url = urljoin(base_url, path)
            try:
                response = self.engine.get(test_url)
                
                if response and response.status_code == 200:
                    text = response.text.lower()
                    for sig in signatures:
                        if sig in text:
                            findings.append({
                                "type": "Information Disclosure",
                                "severity": "High" if path in ["/.env", "/.git/config"] else "Low",
                                "url": test_url,
                                "evidence": f"Found sensitive file {path} containing '{sig}'",
                                "confidence": "High"
                            })
                            break
            except requests.RequestException:
                pass
        return {"findings": findings}
