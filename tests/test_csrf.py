import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(
    0,
    str(PROJECT_ROOT)
)

from app.scanner.csrf_scanner import CSRFScanner
from app.scanner.engine import ScannerEngine


def main():
    engine = ScannerEngine()
    scanner = CSRFScanner(engine)

    form = {
        "action": "http://127.0.0.1:8000/update",
        "method": "POST",
        "inputs": [
            {
                "name": "username",
                "type": "input"
            },
            {
                "name": "email",
                "type": "input"
            }
        ]
    }

    result = scanner.scan_form(
        form,
        "http://127.0.0.1:8000"
    )

    print("\nCSRF Scan")
    print("---------")
    print("URL:", result["url"])
    print("Method:", result["method"])
    print("Vulnerable:", result["vulnerable"])

    if result["findings"]:

        for finding in result["findings"]:

            print("\nType:", finding["type"])
            print("Severity:", finding["severity"])
            print("Evidence:", finding["evidence"])

    else:

        print("\nNo CSRF evidence detected.")


if __name__ == "__main__":
    main()