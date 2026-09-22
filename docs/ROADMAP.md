# SentinelScan — Development Roadmap

## Phase 1 — Accuracy

### 1. HSTS HTTPS awareness

HTTP:
skip HSTS.

HTTPS:
check HSTS.

Status:

[x] Completed

---

### 2. Finding deduplication

Prevent duplicate findings caused by:

- multiple requests
- repeated parameters
- repeated scanner results

Use a stable finding identity.

Status:

[x] Completed

---

### 3. XSS improvements

Improve:

- reflection context
- HTML context
- attribute context
- script context
- encoding detection
- confidence classification

Status:

[x] Completed

---

### 4. SQLi improvements

Potential future detection:

- response difference
- Boolean-based testing
- time-based detection
- DBMS-specific signatures

Must remain controlled and authorized.

Status:

[x] Completed

---

### 5. CSRF improvements

Potential checks:

- token extraction
- token structure
- SameSite cookies
- state-changing methods
- form behavior

Status:

[x] Completed

---

# Phase 2 — Scanner Engine

[x] Central request configuration

[x] Timeout configuration

[x] Limited retries

[x] Rate limiting

[x] Request statistics

[x] Response statistics

[x] Scan duration

[x] Error tracking

---

[x] Completed

---

# Phase 3 — Comparison

Current:

- New
- Fixed
- Unchanged
- Severity changes

Future:

[x] Evidence changes

[x] Confidence changes

[x] Severity increase

[x] Severity decrease

[x] Comparison summary

---

# Phase 4 — Reporting

Current:

[x] JSON

[x] PDF

Future:

[x] CSV

[x] Better executive summary

[x] Scan duration

[x] Pages scanned

[x] Forms discovered

[x] Requests made

[x] Comparison information

---

# Phase 5 — Dashboard

Current:

[x] Statistics

[x] Severity distribution

[x] Vulnerability distribution

[x] Findings trend

[x] Search

[x] Status filtering

Future:

[x] Date filtering

[x] Severity filtering

[x] Vulnerability filtering

[x] Target filtering

[x] Pagination

---

# Phase 6 — Background Scanning

Potential architecture:

Browser
↓
Create scan
↓
Background job
↓
Scanner
↓
Database
↓
Dashboard

Potential technologies:

- RQ
- Celery
- Redis
- lightweight task queue

Do not introduce complexity unless needed.

---

# Phase 7 — Scan Progress

Potential UI:

Scan #17

Crawler             ✓
XSS                 ✓
SQLi                ✓
CSRF                ...
Security Headers    ...

Progress:

72%

---

# Phase 8 — Authentication

Potential features:

- login
- registration
- password hashing
- session management
- user-specific scans

Database:

users
scans
findings

Only introduce after scanner stability.

---

# Phase 9 — Application Security

Harden SentinelScan itself:

[ ] CSRF protection

[ ] Secure cookies

[ ] Session security

[ ] Input validation

[ ] Security headers

[ ] Secret management

[ ] Error handling

[ ] Debug disabled

---

# Phase 10 — Automated Tests

Expand tests for:

- crawler
- XSS
- SQLi
- CSRF
- headers
- database
- APIs
- reports
- comparison
- authorization

Test edge cases:

- invalid URL
- unavailable target
- timeout
- redirects
- empty forms
- missing action
- missing method
- multiple parameters
- HTTPS
- HTTP

---

# Phase 11 — Docker

Potential:

Dockerfile

docker-compose.yml

Services:

- SentinelScan
- MySQL
- optional Redis

---

# Phase 12 — Additional Vulnerability Modules

Only after core accuracy is strong.

Potential modules:

- Open Redirect
- Insecure Cookie Configuration
- CORS Misconfiguration
- Information Disclosure
- Directory Listing
- Server Information Disclosure
- Mixed Content
- TLS configuration
- Sensitive headers

---

# Phase 13 — UI

Potential:

- sidebar
- dashboard
- scans
- findings
- reports
- settings
- dark mode
- better responsive layout

---

# Final Goal

A professional security assessment platform with:

Crawler
+
Scanner Engine
+
Finding Engine
+
Database
+
Analytics
+
Reports
+
Historical Comparison
+
Authentication
+
Background Jobs