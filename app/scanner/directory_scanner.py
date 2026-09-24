from urllib.parse import urlparse, urljoin
import requests

class DirectoryScanner:
    def __init__(self, engine):
        self.engine = engine
        self.common_paths = [
            "/images/", "/css/", "/js/", "/uploads/", "/backup/", "/admin/"
        ]

    def scan(self, target_url):
        findings = []
        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for path in self.common_paths:
            test_url = urljoin(base_url, path)
            try:
                response = self.engine.get(test_url)
                
                if response and response.status_code == 200:
                    text = response.text.lower()
                    if "index of /" in text or "parent directory" in text:
                        findings.append({
                            "type": "Directory Listing",
                            "severity": "Medium",
                            "url": test_url,
                            "evidence": f"Found directory listing signature at {path}",
                            "confidence": "High"
                        })
            except requests.RequestException:
                pass
        return {"findings": findings}
