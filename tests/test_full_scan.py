
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))


from urllib.parse import urlparse, parse_qs

from app.scanner.crawler import WebCrawler
from app.scanner.xss_scanner import XSSScanner
from app.scanner.engine import ScannerEngine


TARGET_URL = "http://127.0.0.1:8000"


def main():
    print("[1] Starting crawler...")

    engine = ScannerEngine()
    
    crawler = WebCrawler(
        start_url=TARGET_URL,
        engine=engine,
        max_pages=20
    )

    result = crawler.crawl()

    print("\n[2] Discovered pages:")
    for page in result["pages"]:
        print(page)

    print("\n[3] Discovered forms:")
    for form in result["forms"]:
        print(form)

    scanner = XSSScanner(engine)

    print("\n[4] Starting XSS scan...")

    for page in result["pages"]:
        page_url = page["url"]

        parsed = urlparse(page_url)
        parameters = parse_qs(
            parsed.query,
            keep_blank_values=True
        )

        for parameter in parameters:
            scan_result = scanner.scan_get_parameter(
                page_url,
                parameter
            )

            print("\nXSS Scan Result:")
            print(scan_result)

    for form in result["forms"]:
        if form["method"].upper() != "GET":
            continue

        form_url = form["action"]

        for input_field in form["inputs"]:
            parameter = input_field.get("name")

            if not parameter:
                continue

            scan_result = scanner.scan_get_parameter(
                form_url,
                parameter
            )

            print("\nForm XSS Scan Result:")
            print(scan_result)


if __name__ == "__main__":
    main()