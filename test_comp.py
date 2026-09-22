import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'app')))
from app import app
from models.scan import db, Scan, Finding

with app.app_context():
    scan1 = Scan(target_url="http://127.0.0.1:8000")
    db.session.add(scan1)
    db.session.commit()
    
    scan2 = Scan(target_url="http://127.0.0.1:8000")
    db.session.add(scan2)
    db.session.commit()

    f1_s1 = Finding(scan_id=scan1.id, vulnerability_type="Reflected XSS", severity="Medium", confidence="Potential", url="http://127.0.0.1:8000/search", parameter="q", evidence="Some evidence 1")
    f2_s1 = Finding(scan_id=scan1.id, vulnerability_type="Missing CSP", severity="Low", confidence="Confirmed", url="http://127.0.0.1:8000/", parameter="", evidence="Evidence A")
    f3_s1 = Finding(scan_id=scan1.id, vulnerability_type="Missing HSTS", severity="Low", confidence="Confirmed", url="http://127.0.0.1:8000/", parameter="", evidence="HSTS evidence")
    f4_s1 = Finding(scan_id=scan1.id, vulnerability_type="SQLi", severity="High", confidence="Potential", url="http://127.0.0.1:8000/search", parameter="id", evidence="Evidence Q")
    db.session.add_all([f1_s1, f2_s1, f3_s1, f4_s1])
    db.session.commit()

    f1_s2 = Finding(scan_id=scan2.id, vulnerability_type="Reflected XSS", severity="High", confidence="Confirmed", url="http://127.0.0.1:8000/search", parameter="q", evidence="New evidence 1")
    f2_s2 = Finding(scan_id=scan2.id, vulnerability_type="Missing CSP", severity="Info", confidence="Confirmed", url="http://127.0.0.1:8000/", parameter="", evidence="Evidence A")
    f4_s2 = Finding(scan_id=scan2.id, vulnerability_type="SQLi", severity="High", confidence="Potential", url="http://127.0.0.1:8000/search", parameter="id", evidence="Evidence Q")
    f5_s2 = Finding(scan_id=scan2.id, vulnerability_type="CSRF", severity="Medium", confidence="Confirmed", url="http://127.0.0.1:8000/post", parameter="data", evidence="No token")
    db.session.add_all([f1_s2, f2_s2, f4_s2, f5_s2])
    db.session.commit()

    print(f"Test data created. Scan 1 ID: {scan1.id}, Scan 2 ID: {scan2.id}")
