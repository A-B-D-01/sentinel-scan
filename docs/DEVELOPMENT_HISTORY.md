# SentinelScan — Development History

## Initial Project

The project began as a Python/Flask web vulnerability scanner.

The original goal was to create a cybersecurity project suitable for internship/portfolio use.

The scanner was intentionally restricted to local authorized targets.

---

# Stage 1 — Project Setup

Created:

- Python virtual environment
- Flask application
- configuration
- .env
- MySQL database
- scanner package
- tests package
- local lab

Database:

sentinel_scan

---

# Stage 2 — Local Vulnerable Application

Created:

lab/vulnerable_app.py

The local application runs on:

127.0.0.1:8000

It contains:

/

and:

/search

The search parameter:

q

is reflected in the response.

This was created specifically to test reflected XSS safely.

---

# Stage 3 — Crawler

Implemented:

WebCrawler

The crawler:

- requests pages
- follows same-origin links
- discovers forms
- records status codes
- records page titles
- extracts form inputs

Important discovery:

The correct crawler method is:

crawl()

not:

run()

---

# Stage 4 — XSS Scanner

Implemented:

XSSScanner

It creates a unique marker and injects it into a GET parameter.

Example:

SENTINEL_<random>

The scanner checks whether that marker is reflected in the HTTP response.

Standalone testing successfully detected reflected input.

Important limitation:

The scanner does not perform real browser JavaScript execution.

---

# Stage 5 — SQL Injection Scanner

Implemented:

SQLiScanner

Current method:

- quote character testing
- database error signature detection

Standalone testing correctly produced no SQLi evidence against the local lab.

This is expected because the local lab does not use SQL.

---

# Stage 6 — CSRF Scanner

Implemented:

CSRFScanner

The scanner checks state-changing methods and recognizable CSRF token fields.

Standalone testing successfully detected a potential CSRF condition on a test POST form.

Integrated local lab scanning correctly skips the GET search form.

---

# Stage 7 — Severity

Implemented severity normalization.

Levels:

Critical
High
Medium
Low
Info

---

# Stage 8 — Security Headers

Implemented checks for:

CSP
X-Content-Type-Options
X-Frame-Options
Referrer-Policy
HSTS

The local lab intentionally lacks these headers.

This produces header findings.

Known future correction:

HSTS should only be evaluated for HTTPS.

---

# Stage 9 — Database

Created:

scans

findings

Expanded findings with:

confidence
description
impact
remediation

This allowed findings to contain richer security information.

---

# Stage 10 — Vulnerability Knowledge Base

Created:

app/scanner/vulnerability_info.py

Added descriptions, impact, remediation, and confidence for the supported vulnerability types.

---

# Stage 11 — Scan Service

Created centralized scan orchestration.

The scan service:

- creates scan
- crawls target
- runs scanners
- saves findings
- enriches findings with knowledge-base metadata
- completes scan
- records errors

---

# Stage 12 — Dashboard

Created dashboard showing:

- total scans
- total findings
- severity counts
- vulnerability types
- scan history
- scan form

---

# Stage 13 — Scan Details

Created detailed scan page.

It displays:

- scan information
- severity counts
- vulnerability
- severity
- confidence
- URL
- parameter
- description
- impact
- evidence
- remediation

---

# Stage 14 — JSON Reporting

Added:

/scans/<id>/export/json

JSON contains:

- scan metadata
- summary
- findings
- evidence
- remediation

---

# Stage 15 — PDF Reporting

Added ReportLab.

Created:

app/scanner/pdf_report.py

Added:

/scans/<id>/export/pdf

PDF includes:

- cover
- executive summary
- severity summary
- detailed findings
- evidence
- remediation
- page numbers

---

# Stage 16 — Scan Comparison

Created:

/scans/<current>/compare/<previous>

Initial comparison produced a false:

1 new
1 fixed

finding because XSS test URLs contained random markers.

This was diagnosed as a comparison identity problem.

The comparison was changed to remove the query string when creating the finding identity.

Current identity:

vulnerability type
+
normalized URL
+
parameter

This solved the false XSS new/fixed result.

---

# Stage 17 — Severity Change Detection

Comparison was expanded to detect:

- new
- fixed
- unchanged
- severity changed

---

# Stage 18 — Dashboard Trend Analytics

Added:

/api/scan-trends

Chart.js line chart.

Displays findings across scans.

---

# Stage 19 — Vulnerability Distribution

Added:

/api/vulnerability-distribution

Chart.js doughnut chart.

Displays vulnerability-type distribution.

---

# Stage 20 — Scan History Search

Dashboard scan history was expanded with:

- target URL search
- status filter
- clear filter

---

# Stage 21 — External CSS

Dashboard CSS was moved from inline HTML into:

app/static/css/style.css

index.html now loads:

{{ url_for('static', filename='css/style.css') }}

---

# Stage 22 — HSTS Accuracy

Corrected the HSTS scanner logic to only report Missing Strict-Transport-Security on HTTPS targets. HTTP targets are properly skipped, reducing false positives.

---

# Stage 23 — Finding Deduplication

Implemented finding deduplication in `scan_service.py` to ensure duplicate findings generated by parameter permutations or multiple invocations are not inserted into the database. A finding's identity is now tracked using its type, normalized URL, and parameter.

---

# Stage 24 — XSS Context Analysis

Improved `XSSScanner` to inject special characters (`<"'>`) and use `BeautifulSoup` to parse the reflection context (HTML, attribute, script). The scanner now detects whether the payload was reflected raw or encoded, and returns dynamic severity and confidence scores.

---

# Stage 25 — SQL Injection Enhancements

Improved `SQLiScanner` by adding DBMS-specific error signatures (MySQL, PostgreSQL, SQLite, Oracle, SQL Server). Introduced Boolean-based testing by evaluating response differences to true/false conditions. Introduced Time-based testing by injecting delays and measuring response elapsed time. Updated dynamic confidence and evidence recording for all SQLi findings.

---

# Stage 26 — CSRF Enhancements

Improved `CSRFScanner` by extracting token values and verifying their structural strength (e.g. length constraints). Added dynamic confidence scoring and introduced a pre-check for `SameSite` cookie configurations by requesting the page and inspecting headers.

---

# Stage 27 — Scanner Engine

Created a central `ScannerEngine` to manage HTTP connections using a customized `requests.Session`.
Implemented default timeouts, rate limiting using sleep delays, and automatic limited retries for 429/5xx status codes via `urllib3.util.retry.Retry`.
Refactored all vulnerability scanners and the crawler to inject and utilize this engine.
Updated the database `Scan` model to track `requests_made` and `errors_count` during a scan, and surfaced these statistics in the frontend dashboard.

---

# Stage 28 — Scan Comparison Enhancements

Completed Phase 3 by updating the comparison module to track severity increases, severity decreases, confidence changes, and evidence changes. Updated the `scan_comparison.html` dashboard to display comparison summary metrics in stats cards alongside detailed categorized sections for these changes.

---

# Stage 29 — Reporting Enhancements

Completed Phase 4 by adding pages_scanned and orms_discovered to the database schema. Extracted comparison logic in pp.py to enable automatic comparison summaries in JSON and PDF exports. Added a new CSV export route. Updated the scan details UI to display the new scan metrics and include the new CSV Export button.

---

# Stage 30 — Dashboard Enhancements

Completed Phase 5 by implementing advanced filtering (date range, severity, vulnerability) and scan list pagination. The dashboard now gracefully handles a large number of scans and filters them by aggregating findings under each scan.

---

# Current Development Point

The immediate next feature is:

Phase 6: Background Scanning (async tasks).

Then scan progress tracking and authentication.

---

# Important Lessons From Development

1. Do not assume a scanner finding is confirmed just because a test response changes.
2. Randomized payloads can break scan comparison if finding identity is poorly designed.
3. The scanner should preserve evidence and confidence.
4. Local testing should use a deliberately vulnerable application.
5. Do not fabricate SQLi or other vulnerabilities.
6. The dashboard should reflect actual database state.
7. Reports should use the same finding data as the dashboard.
8. Accuracy is more important than adding many vulnerability types.