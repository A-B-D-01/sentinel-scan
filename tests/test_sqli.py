import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.scanner.sqli_scanner import SQLiScanner
from app.scanner.engine import ScannerEngine

engine = ScannerEngine()
TARGET_URL = "http://127.0.0.1:8000"


def main():

    scanner = SQLiScanner(engine)

    # This URL is only for testing the scanner module.
    # The current vulnerable lab does not necessarily
    # contain a SQL-backed endpoint.
    test_url = TARGET_URL + "/search?q=test"

    result = scanner.scan_get_parameter(
        test_url,
        "q"
    )

    print("\nSQL Injection Scan")
    print("------------------")

    print("URL:", result["url"])
    print("Parameter:", result["parameter"])
    print("Vulnerable:", result["vulnerable"])

    if result["findings"]:

        for finding in result["findings"]:

            print("\nType:", finding["type"])
            print("Severity:", finding["severity"])
            print("Evidence:", finding["evidence"])

    else:

        print("\nNo SQL injection evidence detected.")


if __name__ == "__main__":
    main()