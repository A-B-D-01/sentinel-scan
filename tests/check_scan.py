import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from flask import Flask
from app.config import Config
from app.models.scan import db, Scan


app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)


with app.app_context():
    from sqlalchemy import desc
    scan = Scan.query.order_by(desc(Scan.id)).first()

    if scan is None:
        print("No scans found.")
    else:
        print("Scan:", scan.id)
        print("Status:", scan.status)
        print("Target:", scan.target_url)
        print("Findings:", len(scan.findings))

        print("\nFinding Details:")

        for finding in scan.findings:

            parameter = finding.parameter or "-"

            print(
                f"- {finding.vulnerability_type} "
                f"| Severity: {finding.severity} "
                f"| Parameter: {parameter}"
            )