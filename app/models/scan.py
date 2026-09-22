from datetime import datetime

from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(50), default="pending")
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    requests_made = db.Column(db.Integer, default=0)
    errors_count = db.Column(db.Integer, default=0)
    pages_scanned = db.Column(db.Integer, default=0)
    forms_discovered = db.Column(db.Integer, default=0)

    findings = db.relationship(
        "Finding",
        backref="scan",
        lazy=True,
        cascade="all, delete-orphan"
    )


class Finding(db.Model):
    __tablename__ = "findings"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    scan_id = db.Column(
        db.Integer,
        db.ForeignKey("scans.id"),
        nullable=False
    )

    vulnerability_type = db.Column(
        db.String(100),
        nullable=False
    )

    severity = db.Column(
        db.String(30),
        nullable=False
    )

    confidence = db.Column(
        db.String(30),
        nullable=True
    )

    url = db.Column(
        db.String(500),
        nullable=False
    )

    parameter = db.Column(
        db.String(100),
        nullable=True
    )

    description = db.Column(
        db.Text,
        nullable=True
    )

    impact = db.Column(
        db.Text,
        nullable=True
    )

    evidence = db.Column(
        db.Text,
        nullable=True
    )

    remediation = db.Column(
        db.Text,
        nullable=True
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )