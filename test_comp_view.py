import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'app')))
from app import app
from models.scan import db, Scan, Finding

client = app.test_client()
response = client.get('/scans/22/compare/21')
print("Status code:", response.status_code)

html = response.data.decode('utf-8')
if "<h3>Severity Increased</h3>" in html:
    print("Severity Increased section found!")
if "<h3>Severity Decreased</h3>" in html:
    print("Severity Decreased section found!")
if "<h2>Confidence Changes</h2>" in html:
    print("Confidence Changes block found!")
if "<h2>Evidence Changes</h2>" in html:
    print("Evidence Changes block found!")

import re
matches = re.findall(r'<div class="number">\s*(\d+)\s*</div>', html)
print("Stats card numbers:", matches)

