import csv
from io import StringIO
from datetime import datetime, timedelta
from urllib.parse import urlparse

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    send_file,
    jsonify,
    Response
)
from concurrent.futures import ThreadPoolExecutor
from threading import Thread
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman

from config import Config
from models.scan import db, Scan, Finding
from models.user import User

from scanner.scan_service import run_scan

app = Flask(__name__)

app.config.from_object(Config)

# Security
csrf = CSRFProtect(app)
csp = {
    'default-src': [
        '\'self\'',
        'https://cdn.jsdelivr.net',
        '\'unsafe-inline\''
    ]
}
talisman = Talisman(app, content_security_policy=csp, force_https=False)

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Global ThreadPool for bounding concurrent scans
scan_executor = ThreadPoolExecutor(max_workers=5)

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def is_allowed_target(url):
    """
    Only allow local test targets.
    """

    try:
        parsed = urlparse(url)

        allowed_hosts = {
            "localhost",
            "127.0.0.1"
        }

        return (
            parsed.scheme in {"http", "https"}
            and parsed.hostname in allowed_hosts
        )

    except Exception:
        return False


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "error")
            return redirect(url_for("register"))
            
        if User.query.filter_by(username=username).first():
            flash("Username already exists", "error")
            return redirect(url_for("register"))
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for("index"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for("index"))
        flash("Invalid username or password", "error")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/api/scan-trends")
@login_required
def scan_trends():

    scans = Scan.query.filter_by(user_id=current_user.id).order_by(
        Scan.id.asc()
    ).all()

    labels = []
    total_findings = []
    critical = []
    high = []
    medium = []
    low = []
    info = []

    for scan in scans:

        labels.append(
            f"Scan #{scan.id}"
        )

        severity_counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Info": 0
        }

        for finding in scan.findings:

            if finding.severity in severity_counts:
                severity_counts[finding.severity] += 1

        total_findings.append(
            len(scan.findings)
        )

        critical.append(
            severity_counts["Critical"]
        )

        high.append(
            severity_counts["High"]
        )

        medium.append(
            severity_counts["Medium"]
        )

        low.append(
            severity_counts["Low"]
        )

        info.append(
            severity_counts["Info"]
        )

    return jsonify({
        "labels": labels,
        "total_findings": total_findings,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "info": info
    })

@app.route("/api/vulnerability-distribution")
@login_required
def vulnerability_distribution():

    findings = Finding.query.join(Scan).filter(Scan.user_id == current_user.id).all()

    distribution = {}

    for finding in findings:

        vulnerability_type = finding.vulnerability_type

        distribution[vulnerability_type] = (
            distribution.get(vulnerability_type, 0) + 1
        )

    return jsonify({
        "labels": list(distribution.keys()),
        "values": list(distribution.values())
    })

@app.route("/")
@login_required
def index():
    search = request.args.get("search", "").strip()
    status_filter = request.args.get("status", "").strip()
    date_from = request.args.get("date_from", "").strip()
    date_to = request.args.get("date_to", "").strip()
    severity_filter = request.args.get("severity", "").strip()
    vulnerability_filter = request.args.get("vulnerability", "").strip()
    page = request.args.get("page", 1, type=int)

    scans_query = Scan.query.filter_by(user_id=current_user.id)

    if search:
        scans_query = scans_query.filter(Scan.target_url.ilike(f"%{search}%"))

    if status_filter:
        scans_query = scans_query.filter_by(status=status_filter)

    if date_from:
        try:
            from_dt = datetime.strptime(date_from, "%Y-%m-%d")
            scans_query = scans_query.filter(Scan.started_at >= from_dt)
        except ValueError:
            pass

    if date_to:
        try:
            to_dt = datetime.strptime(date_to, "%Y-%m-%d") + timedelta(days=1)
            scans_query = scans_query.filter(Scan.started_at < to_dt)
        except ValueError:
            pass

    if severity_filter:
        scans_query = scans_query.filter(Scan.findings.any(Finding.severity == severity_filter))

    if vulnerability_filter:
        scans_query = scans_query.filter(Scan.findings.any(Finding.vulnerability_type == vulnerability_filter))

    pagination = scans_query.order_by(Scan.id.desc()).paginate(page=page, per_page=10, error_out=False)
    scans = pagination.items

    total_scans = Scan.query.filter_by(user_id=current_user.id).count()

    total_findings = Finding.query.join(Scan).filter(Scan.user_id == current_user.id).count()

    critical_count = Finding.query.join(Scan).filter(
        Scan.user_id == current_user.id,
        Finding.severity == "Critical"
    ).count()

    high_count = Finding.query.join(Scan).filter(
        Scan.user_id == current_user.id,
        Finding.severity == "High"
    ).count()

    medium_count = Finding.query.join(Scan).filter(
        Scan.user_id == current_user.id,
        Finding.severity == "Medium"
    ).count()

    low_count = Finding.query.join(Scan).filter(
        Scan.user_id == current_user.id,
        Finding.severity == "Low"
    ).count()

    info_count = Finding.query.join(Scan).filter(
        Scan.user_id == current_user.id,
        Finding.severity == "Info"
    ).count()

    vulnerability_types = {}

    for finding in Finding.query.join(Scan).filter(Scan.user_id == current_user.id).all():

        vulnerability_type = (
            finding.vulnerability_type
        )

        vulnerability_types[vulnerability_type] = (
            vulnerability_types.get(
                vulnerability_type,
                0
            ) + 1
        )

    return render_template(
        "index.html",
        scans=scans,
        pagination=pagination,
        total_scans=total_scans,
        total_findings=total_findings,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        info_count=info_count,
        vulnerability_types=vulnerability_types,
        search=search,
        status_filter=status_filter,
        date_from=date_from,
        date_to=date_to,
        severity_filter=severity_filter,
        vulnerability_filter=vulnerability_filter
    )

@app.route("/api/scan-progress/<int:scan_id>")
@login_required
def scan_progress(scan_id):
    scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first()
    if not scan:
        return jsonify({"error": "Not found"}), 404
    return jsonify({
        "id": scan.id,
        "status": scan.status,
        "progress": scan.progress,
        "progress_status": scan.progress_status
    })

@app.route("/scan", methods=["POST"])
@login_required
def start_scan():
    target_url = request.form.get("target_url", "").strip()

    if not is_allowed_target(target_url):
        flash(
            "Only authorized localhost targets are allowed.",
            "error"
        )
        return redirect(url_for("index"))

    try:
        scan = Scan(
            target_url=target_url,
            status="pending",
            started_at=datetime.utcnow(),
            user_id=current_user.id
        )
        db.session.add(scan)
        db.session.commit()
        scan_id = scan.id

        def background_scan(app_context, s_id):
            with app_context:
                try:
                    run_scan(s_id)
                except Exception as e:
                    # Fallback error handling if scan_service fails catastrophically
                    scan_record = db.session.get(Scan, s_id)
                    if scan_record and scan_record.status != "completed":
                        scan_record.status = "failed"
                        scan_record.progress_status = f"System Error: {str(e)}"
                        scan_record.completed_at = datetime.utcnow()
                        db.session.commit()
                finally:
                    db.session.remove()

        scan_executor.submit(background_scan, app.app_context(), scan_id)

        flash(f"Scan #{scan_id} started in the background.", "success")

    except Exception as error:
        flash(f"Failed to start scan: {error}", "error")

    return redirect(url_for("index"))

@app.route("/scans/<int:scan_id>")
@login_required
def scan_details(scan_id):

    scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()

    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0
    }

    for finding in scan.findings:

        severity = finding.severity

        if severity in severity_counts:
            severity_counts[severity] += 1

    previous_scan = Scan.query.filter(
        Scan.user_id == current_user.id,
        Scan.target_url == scan.target_url,
        Scan.id < scan.id
    ).order_by(Scan.id.desc()).first()

    return render_template(
        "scan_details.html",
        scan=scan,
        severity_counts=severity_counts,
        previous_scan=previous_scan
    )

def get_comparison_data(current_scan, previous_scan):
    def finding_key(finding):
        url = finding.url or ""
        if "?" in url:
            url = url.split("?", 1)[0]
        return (finding.vulnerability_type, url, finding.parameter or "")

    current_findings = {finding_key(finding): finding for finding in current_scan.findings}
    previous_findings = {finding_key(finding): finding for finding in previous_scan.findings}

    current_keys = set(current_findings.keys())
    previous_keys = set(previous_findings.keys())

    new_keys = current_keys - previous_keys
    fixed_keys = previous_keys - current_keys
    unchanged_keys = current_keys & previous_keys

    severity_increase = []
    severity_decrease = []
    confidence_changes = []
    evidence_changes = []
    severity_levels = {"Info": 1, "Low": 2, "Medium": 3, "High": 4, "Critical": 5}

    for key in unchanged_keys:
        previous_finding = previous_findings[key]
        current_finding = current_findings[key]
        
        if previous_finding.severity != current_finding.severity:
            prev_level = severity_levels.get(previous_finding.severity, 0)
            curr_level = severity_levels.get(current_finding.severity, 0)
            change_data = {
                "finding": current_finding,
                "previous_severity": previous_finding.severity,
                "current_severity": current_finding.severity
            }
            if curr_level > prev_level:
                severity_increase.append(change_data)
            else:
                severity_decrease.append(change_data)

        if previous_finding.confidence != current_finding.confidence:
            confidence_changes.append({
                "finding": current_finding,
                "previous_confidence": previous_finding.confidence,
                "current_confidence": current_finding.confidence
            })

        if previous_finding.evidence != current_finding.evidence:
            evidence_changes.append({
                "finding": current_finding,
                "previous_evidence": previous_finding.evidence,
                "current_evidence": current_finding.evidence
            })

    return {
        "previous_scan": previous_scan,
        "current_scan": current_scan,
        "new_findings": [current_findings[key] for key in new_keys],
        "fixed_findings": [previous_findings[key] for key in fixed_keys],
        "unchanged_findings": [current_findings[key] for key in unchanged_keys],
        "severity_increase": severity_increase,
        "severity_decrease": severity_decrease,
        "confidence_changes": confidence_changes,
        "evidence_changes": evidence_changes
    }

@app.route("/scans/<int:scan_id>/compare/<int:previous_scan_id>")
@login_required
def compare_scans(scan_id, previous_scan_id):
    current_scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    previous_scan = Scan.query.filter_by(id=previous_scan_id, user_id=current_user.id).first_or_404()
    comparison = get_comparison_data(current_scan, previous_scan)
    return render_template("scan_comparison.html", **comparison)


@app.route("/scans/<int:scan_id>/export/csv")
@login_required
def export_scan_csv(scan_id):
    scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(["ID", "Vulnerability Type", "Severity", "Confidence", "URL", "Parameter", "Created At"])
    for f in scan.findings:
        cw.writerow([
            f.id,
            f.vulnerability_type,
            f.severity,
            f.confidence,
            f.url,
            f.parameter,
            f.created_at.isoformat() if f.created_at else ""
        ])
    output = si.getvalue()
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=sentinelscan_report_{scan.id}.csv"}
    )

@app.route("/scans/<int:scan_id>/export/json")
@login_required
def export_scan_json(scan_id):

    scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()

    report = {
        "scanner": "SentinelScan",
        "report_version": "1.0",
        "scan": {
            "id": scan.id,
            "target_url": scan.target_url,
            "status": scan.status,
            "started_at": (
                scan.started_at.isoformat()
                if scan.started_at
                else None
            ),
            "completed_at": (
                scan.completed_at.isoformat()
                if scan.completed_at
                else None
            )
        },
        "duration_seconds": (scan.completed_at - scan.started_at).total_seconds() if scan.completed_at and scan.started_at else 0,
        "pages_scanned": scan.pages_scanned,
        "forms_discovered": scan.forms_discovered,
        "requests_made": scan.requests_made,
        "summary": {
            "total_findings": len(scan.findings),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        },
        "findings": []
    }

    for finding in scan.findings:

        severity_key = finding.severity.lower()

        if severity_key in report["summary"]:
            report["summary"][severity_key] += 1

        report["findings"].append({
            "id": finding.id,
            "vulnerability_type": finding.vulnerability_type,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "url": finding.url,
            "parameter": finding.parameter,
            "description": finding.description,
            "impact": finding.impact,
            "evidence": finding.evidence,
            "remediation": finding.remediation,
            "created_at": (
                finding.created_at.isoformat()
                if finding.created_at
                else None
            )
        })

    previous_scan = Scan.query.filter(Scan.user_id == current_user.id, Scan.target_url == scan.target_url, Scan.id < scan.id).order_by(Scan.id.desc()).first()
    if previous_scan:
        comp_data = get_comparison_data(scan, previous_scan)
        report["comparison"] = {
            "previous_scan_id": previous_scan.id,
            "new_findings_count": len(comp_data["new_findings"]),
            "fixed_findings_count": len(comp_data["fixed_findings"]),
            "severity_increased_count": len(comp_data["severity_increase"]),
            "severity_decreased_count": len(comp_data["severity_decrease"])
        }

    response = jsonify(report)

    response.headers[
        "Content-Disposition"
    ] = (
        f"attachment; "
        f"filename=sentinelscan_report_{scan.id}.json"
    )

    return response

@app.route("/health")
def health():

    return {
        "status": "ok",
        "service": "SentinelScan"
    }


@app.route("/scans/<int:scan_id>/export/pdf")
@login_required
def export_scan_pdf(scan_id):

    scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()

    from scanner.pdf_report import generate_scan_pdf

    previous_scan = Scan.query.filter(Scan.user_id == current_user.id, Scan.target_url == scan.target_url, Scan.id < scan.id).order_by(Scan.id.desc()).first()
    comp_data = get_comparison_data(scan, previous_scan) if previous_scan else None

    pdf_buffer = generate_scan_pdf(
        scan,
        previous_scan=previous_scan,
        comparison_stats=comp_data
    )

    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=(
            f"sentinelscan_report_{scan.id}.pdf"
        )
    )

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )