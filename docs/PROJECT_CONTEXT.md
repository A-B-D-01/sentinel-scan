# SentinelScan — Project Context

## Purpose

SentinelScan is a full-stack Python/Flask web application vulnerability scanner.

The project is being developed as a cybersecurity portfolio/internship project.

The objective is to build a practical security assessment platform rather than a collection of isolated scripts.

The scanner is currently restricted to authorized localhost targets.

Allowed targets currently include:

- localhost
- 127.0.0.1

Do NOT remove this restriction without explicit instruction.

---

# Development Environment

Operating System:

Windows

Project path:

D:\Projects\sentinel-scan

Python virtual environment:

D:\Projects\sentinel-scan\venv

Backend:

- Python
- Flask
- Flask-SQLAlchemy
- Requests
- BeautifulSoup
- ReportLab

Database:

- MySQL
- PyMySQL

Frontend:

- HTML
- CSS
- JavaScript
- Chart.js

---

# Local Applications

SentinelScan dashboard:

http://127.0.0.1:5000

Local vulnerable testing lab:

http://127.0.0.1:8000

---

# How to Start

Terminal 1:

cd D:\Projects\sentinel-scan
.\venv\Scripts\Activate.ps1
python lab\vulnerable_app.py

Terminal 2:

cd D:\Projects\sentinel-scan
.\venv\Scripts\Activate.ps1
cd app
python app.py

Dashboard:

http://127.0.0.1:5000

Lab:

http://127.0.0.1:8000

---

# Current Architecture

Browser
    ↓
Flask
    ↓
Scan Service
    ↓
Crawler
    ↓
XSS / SQLi / CSRF / Security Headers
    ↓
Finding Metadata
    ↓
MySQL
    ↓
Dashboard / JSON / PDF / Comparison

---

# Current Scanner Modules

## Crawler

File:

app/scanner/crawler.py

Class:

WebCrawler

Main method:

crawl()

The crawler discovers pages and forms while maintaining same-origin restrictions.

---

## XSS

File:

app/scanner/xss_scanner.py

Class:

XSSScanner

Current approach:

Reflected input detection using a unique SentinelScan marker.

Important:

This is NOT browser-confirmed JavaScript execution.

Therefore XSS findings should maintain appropriate confidence.

---

## SQL Injection

File:

app/scanner/sqli_scanner.py

Class:

SQLiScanner

Current approach:

Error-based detection using SQL-related test characters and database error signatures.

The local lab currently does not use a database.

Therefore SQLi should not appear in the normal lab scan.

Do not manufacture SQLi findings.

---

## CSRF

File:

app/scanner/csrf_scanner.py

Class:

CSRFScanner

Current approach:

Analyze state-changing forms and look for recognizable CSRF token fields.

Absence of a token does not automatically prove exploitable CSRF.

Use "Potential CSRF" with appropriate confidence.

---

## Security Headers

File:

app/scanner/security_headers.py

Current checks:

- Content-Security-Policy
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy
- Strict-Transport-Security

Note:

HSTS is correctly skipped for HTTP targets to prevent false positives and is only evaluated for HTTPS targets.

---

# Database

Database:

sentinel_scan

Tables:

scans

findings

Scan fields:

- id
- target_url
- status
- started_at
- completed_at
- requests_made
- errors_count
- pages_scanned
- forms_discovered

Finding fields:

- id
- scan_id
- vulnerability_type
- severity
- confidence
- url
- parameter
- description
- impact
- evidence
- remediation
- created_at

---

# Reporting

JSON export:

/scans/<scan_id>/export/json

PDF export:

/scans/<scan_id>/export/pdf

CSV export:

/scans/<scan_id>/export/csv

PDF generator:

app/scanner/pdf_report.py

---

# Scan Comparison

Current route:

/scans/<current_id>/compare/<previous_id>

Current comparison categories:

- new findings
- fixed findings
- unchanged findings
- severity increase
- severity decrease
- confidence changes
- evidence changes

Important Architecture Decision:

XSS test URLs contain randomized markers, and repeated parameters or multiple requests can generate duplicate findings.

Therefore, the scanner implements intra-scan deduplication and inter-scan comparison using a stable finding identity based on:

- vulnerability type
- normalized URL without query string
- parameter

This identity format is used in `app/scanner/scan_service.py` to prevent duplicate database insertions during a scan.

---

# Dashboard

Dashboard:

/

Current dashboard features:

- Total scans
- Total findings
- Critical
- High
- Medium
- Low
- Info
- Severity distribution
- Vulnerability types
- Security findings trend
- Vulnerability distribution
- Scan history
- Target URL search
- Status filtering

Chart APIs:

/api/scan-trends

/api/vulnerability-distribution

---

# Frontend

Main dashboard:

app/templates/index.html

CSS:

app/static/css/style.css

Chart library:

Chart.js

---

# Local Vulnerable Lab

File:

lab/vulnerable_app.py

Current behavior:

/

contains a GET form.

The form submits to:

/search

Parameter:

q

/search reflects q in the response.

This intentionally provides a reflected-input test case.

---

# Accuracy Philosophy

SentinelScan should distinguish:

Potential finding

Likely finding

Confirmed finding

Do not overstate scanner results.

Examples:

Reflection ≠ automatically confirmed XSS.

Missing recognizable CSRF token ≠ automatically confirmed CSRF.

Database error signature ≠ automatically confirmed SQL injection.

Missing HSTS on HTTP ≠ a meaningful HSTS finding.

---

# Current Status & Next Steps

Current Status: Phase 1 (Scanner Accuracy) is actively in progress.
Recently Completed:
- Dashboard search and filtering enhancements.
- HSTS HTTPS-awareness logic fixed in `app/scanner/security_headers.py`.
- Intra-scan finding deduplication implemented in `app/scanner/scan_service.py`.

Tests Performed:
- Automated tests via `tests/test_full_scan.py` and `tests/test_security_headers.py`.
- Manual scan verification and database state checking via `tests/check_scan.py`.

Immediate Next Task:
XSS Context Analysis. We need to improve detection accuracy by analyzing reflection context, HTML context, attribute/script context, encoding detection, and refining confidence classification.

Future Roadmap Changes:
- SQLi accuracy improvements.
- Scanner engine optimizations.
- Reporting enhancements and background scanning.

---

# Development Rules

1. Preserve working functionality.
2. Inspect current code before modifying it.
3. Prefer complete file replacements when making substantial changes.
4. Test after every major change.
5. Do not expose .env credentials.
6. Do not remove localhost authorization.
7. Do not manufacture vulnerability findings.
8. Keep dependencies reasonable.
9. Prioritize accuracy over number of features.
10. Keep the architecture understandable for a student portfolio project.