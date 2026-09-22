import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from app.models.scan import db, Scan, Finding
from app.config import Config
from flask import Flask


def main():
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)

    with app.app_context():
        db.create_all()

        scan = Scan(
            target_url="http://127.0.0.1:8000",
            status="completed"
        )

        db.session.add(scan)
        db.session.commit()

        finding = Finding(
            scan_id=scan.id,
            vulnerability_type="Reflected XSS",
            severity="High",
            url="http://127.0.0.1:8000/search?q=test",
            parameter="q",
            evidence="Unique marker reflected in HTML."
        )

        db.session.add(finding)
        db.session.commit()

        print("Database test successful.")
        print("Scan ID:", scan.id)
        print("Finding ID:", finding.id)


if __name__ == "__main__":
    main()