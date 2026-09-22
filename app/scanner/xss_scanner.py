import uuid
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests
from bs4 import BeautifulSoup


class XSSScanner:

    def __init__(self, engine):
        self.engine = engine

    def scan_get_parameter(self, url, parameter):

        base_marker = "SENTINEL_" + uuid.uuid4().hex[:12]
        payload = base_marker + "<\"'>"

        parsed = urlparse(url)

        params = parse_qs(
            parsed.query,
            keep_blank_values=True
        )

        params[parameter] = [payload]

        test_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            urlencode(params, doseq=True),
            parsed.fragment
        ))

        try:

            response = self.engine.get(
                test_url
            )

        except requests.RequestException as error:

            return {
                "vulnerable": False,
                "error": str(error)
            }

        reflected = base_marker in response.text
        
        if not reflected:
            return {
                "vulnerable": False,
                "url": test_url,
                "parameter": parameter,
                "marker": payload,
                "severity": "Info",
                "evidence": "Marker not reflected.",
                "confidence": "Low"
            }

        # Analyze context
        soup = BeautifulSoup(
            response.text,
            "html.parser"
        )
        
        contexts = set()
        
        # Check text context
        for text_node in soup.find_all(string=True):
            if base_marker in text_node:
                parent = text_node.parent
                if parent and parent.name == 'script':
                    contexts.add("script")
                elif parent and parent.name == 'style':
                    contexts.add("style")
                else:
                    contexts.add("html")

        # Check attribute context
        for tag in soup.find_all(True):
            for attr, value in tag.attrs.items():
                if isinstance(value, list):
                    value = " ".join(value)
                if value and base_marker in value:
                    contexts.add("attribute")

        context_list = list(contexts)
        
        # Check encoding
        unencoded_reflected = payload in response.text
        
        # Determine Severity and Confidence
        severity = "High"
        confidence = "High"
        
        if unencoded_reflected:
            evidence = f"Unique marker reflected unencoded. Contexts: {', '.join(context_list) if context_list else 'unknown'}."
        else:
            severity = "Low"
            confidence = "Low"
            evidence = f"Unique marker reflected but special characters were encoded or removed. Contexts: {', '.join(context_list) if context_list else 'unknown'}."

        return {
            "vulnerable": True,
            "url": test_url,
            "parameter": parameter,
            "marker": payload,
            "severity": severity,
            "evidence": evidence,
            "confidence": confidence
        }