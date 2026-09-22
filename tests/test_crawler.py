import os
import sys

# Add the project root to the python path so we can import 'app'
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.scanner.crawler import WebCrawler


crawler = WebCrawler(
    "http://127.0.0.1:8000",
    max_pages=10
)

results = crawler.crawl()

print("\nDiscovered pages:")

for page in results["pages"]:
    print(page)

print("\nDiscovered forms:")

for form in results["forms"]:
    print(form)