import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.scanner.xss_scanner import XSSScanner
from app.scanner.engine import ScannerEngine

engine = ScannerEngine()
scanner = XSSScanner(engine)

result = scanner.scan_get_parameter(
    "http://127.0.0.1:8000/search",
    "q"
)

print("\nXSS Scan Result:")
print(result)