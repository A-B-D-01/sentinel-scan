import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from app.scanner.security_headers import SecurityHeadersScanner


TARGET_URL = "http://127.0.0.1:8000"


def main():

    scanner = SecurityHeadersScanner()

    result = scanner.scan(TARGET_URL)

    print("\nSecurity Headers Scan")
    print("---------------------")

    print("URL:", result["url"])
    print("Status Code:", result["status_code"])

    print("\nFindings:")

    for finding in result["findings"]:

        print("\nType:", finding["type"])
        print("Severity:", finding["severity"])
        print("Evidence:", finding["evidence"])


if __name__ == "__main__":
    main()