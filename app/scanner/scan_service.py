from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from scanner.engine import ScannerEngine
from scanner.crawler import WebCrawler
from scanner.xss_scanner import XSSScanner
from scanner.sqli_scanner import SQLiScanner
from scanner.csrf_scanner import CSRFScanner
from scanner.security_headers import SecurityHeadersScanner
from scanner.directory_scanner import DirectoryScanner
from scanner.info_disclosure import InfoDisclosureScanner
from scanner.severity import normalize_severity
from scanner.vulnerability_info import get_vulnerability_info

from models.scan import db, Scan, Finding


def build_form_test_url(form_url, parameter):
    parsed = urlparse(form_url)

    params = parse_qs(
        parsed.query,
        keep_blank_values=True
    )

    params[parameter] = [""]

    query = urlencode(
        params,
        doseq=True
    )

    return urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        query,
        parsed.fragment
    ))


def save_finding(
    scan,
    vulnerability_type,
    severity,
    url,
    parameter,
    evidence,
    seen_findings=None,
    confidence=None
):
    """
    Create and save a Finding using information
    from the vulnerability knowledge base.
    """

    if seen_findings is not None:
        parsed = urlparse(url)
        normalized_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        param_str = parameter if parameter else ""
        identity = f"{vulnerability_type}|{normalized_url}|{param_str}"

        if identity in seen_findings:
            return None

        seen_findings.add(identity)

    info = get_vulnerability_info(
        vulnerability_type
    )

    finding = Finding(
        scan_id=scan.id,

        vulnerability_type=vulnerability_type,

        severity=normalize_severity(
            severity
        ),

        confidence=confidence if confidence else info["confidence"],

        url=url,

        parameter=parameter,

        description=info["description"],

        impact=info["impact"],

        evidence=evidence,

        remediation=info["remediation"]
    )

    db.session.add(finding)

    return finding


def run_scan(scan_id):

    scan = db.session.get(Scan, scan_id)
    if not scan:
        return {"status": "error", "error": "Scan not found"}

    target_url = scan.target_url

    try:
        scan.progress = 5
        scan.progress_status = "Initializing"
        db.session.commit()

        print(
            f"[SCAN] Starting scan #{scan.id}"
        )

        print(
            f"[SCAN] Target: {target_url}"
        )

        # ==================================================
        # 1. CRAWLER
        # ==================================================
        scan.progress = 10
        scan.progress_status = "Crawling website..."
        db.session.commit()

        engine = ScannerEngine(timeout=5, retries=2, rate_limit_delay=0.0)

        crawler = WebCrawler(
            start_url=target_url,
            engine=engine,
            max_pages=20
        )

        result = crawler.crawl()

        if not result["pages"]:

            scan.status = "failed"
            scan.progress_status = "Failed: Target could not be reached."
            scan.completed_at = datetime.utcnow()

            db.session.commit()

            return {
                "scan_id": scan.id,
                "status": "failed",
                "findings_count": 0,
                "error": "Target could not be reached."
            }

        print(
            f"[SCAN] Pages discovered: "
            f"{len(result['pages'])}"
        )

        print(
            f"[SCAN] Forms discovered: "
            f"{len(result['forms'])}"
        )

        # ==================================================
        # 2. INITIALIZE SCANNERS
        # ==================================================

        xss_scanner = XSSScanner(engine)

        sqli_scanner = SQLiScanner(engine)

        csrf_scanner = CSRFScanner(engine)

        headers_scanner = SecurityHeadersScanner(engine)
        
        dir_scanner = DirectoryScanner(engine)
        
        info_scanner = InfoDisclosureScanner(engine)

        findings_count = 0
        seen_findings = set()

        # ==================================================
        # 3. SCAN URL PARAMETERS
        # ==================================================
        
        scan.progress = 30
        scan.progress_status = "Scanning URL parameters..."
        db.session.commit()

        for page in result["pages"]:

            page_url = page["url"]

            parsed = urlparse(page_url)

            parameters = parse_qs(
                parsed.query,
                keep_blank_values=True
            )

            for parameter in parameters:

                # ------------------------------------------
                # XSS
                # ------------------------------------------

                print(
                    f"[XSS] Testing parameter "
                    f"{parameter} on {page_url}"
                )

                xss_result = (
                    xss_scanner.scan_get_parameter(
                        page_url,
                        parameter
                    )
                )

                if xss_result.get("vulnerable"):

                    finding = save_finding(
                        scan=scan,
                        vulnerability_type="Reflected XSS",
                        severity=xss_result.get("severity", "high"),
                        url=xss_result["url"],
                        parameter=xss_result["parameter"],
                        evidence=xss_result["evidence"],
                        seen_findings=seen_findings,
                        confidence=xss_result.get("confidence")
                    )

                    if finding:
                        findings_count += 1

                        print(
                            f"[XSS] Vulnerability found "
                            f"in parameter: {parameter}"
                        )

                # ------------------------------------------
                # SQL INJECTION
                # ------------------------------------------

                print(
                    f"[SQLi] Testing parameter "
                    f"{parameter} on {page_url}"
                )

                sqli_result = (
                    sqli_scanner.scan_get_parameter(
                        page_url,
                        parameter
                    )
                )

                for sqli_finding in (
                    sqli_result.get(
                        "findings",
                        []
                    )
                ):

                    finding = save_finding(
                        scan=scan,
                        vulnerability_type=sqli_finding["type"],
                        severity=sqli_finding["severity"],
                        url=sqli_finding["url"],
                        parameter=sqli_finding["parameter"],
                        evidence=sqli_finding["evidence"],
                        seen_findings=seen_findings,
                        confidence=sqli_finding.get("confidence")
                    )

                    if finding:
                        findings_count += 1

                        print(
                            f"[SQLi] Finding: "
                            f"{sqli_finding['type']} "
                            f"in parameter: {parameter}"
                        )

        # ==================================================
        # 4. SCAN FORMS
        # ==================================================
        
        scan.progress = 60
        scan.progress_status = "Scanning forms..."
        db.session.commit()

        for form in result["forms"]:

            form_action = form.get(
                "action",
                target_url
            )

            form_page_url = form.get(
                "page_url",
                target_url
            )

            # ----------------------------------------------
            # CSRF
            # ----------------------------------------------

            print(
                f"[CSRF] Checking form "
                f"{form_action}"
            )

            csrf_result = csrf_scanner.scan_form(
                form,
                form_page_url
            )

            for csrf_finding in (
                csrf_result.get(
                    "findings",
                    []
                )
            ):

                finding = save_finding(
                    scan=scan,
                    vulnerability_type=csrf_finding["type"],
                    severity=csrf_finding["severity"],
                    url=csrf_finding["url"],
                    parameter=csrf_finding["parameter"],
                    evidence=csrf_finding["evidence"],
                    seen_findings=seen_findings,
                    confidence=csrf_finding.get("confidence")
                )

                if finding:
                    findings_count += 1

                    print(
                        f"[CSRF] Finding: "
                        f"{csrf_finding['type']}"
                    )

            # ----------------------------------------------
            # XSS + SQLi for GET forms
            # ----------------------------------------------

            if form["method"].upper() != "GET":
                continue

            form_url = form["action"]

            for input_field in form["inputs"]:

                parameter = input_field.get(
                    "name"
                )

                if not parameter:
                    continue

                test_url = build_form_test_url(
                    form_url,
                    parameter
                )

                # ------------------------------------------
                # XSS
                # ------------------------------------------

                print(
                    f"[XSS] Testing form parameter "
                    f"{parameter}"
                )

                xss_result = (
                    xss_scanner.scan_get_parameter(
                        test_url,
                        parameter
                    )
                )

                if xss_result.get("vulnerable"):

                    finding = save_finding(
                        scan=scan,
                        vulnerability_type="Reflected XSS",
                        severity=xss_result.get("severity", "high"),
                        url=xss_result["url"],
                        parameter=xss_result["parameter"],
                        evidence=xss_result["evidence"],
                        seen_findings=seen_findings,
                        confidence=xss_result.get("confidence")
                    )

                    if finding:
                        findings_count += 1

                        print(
                            f"[XSS] Vulnerability found "
                            f"in form parameter: {parameter}"
                        )

                # ------------------------------------------
                # SQL INJECTION
                # ------------------------------------------

                print(
                    f"[SQLi] Testing form parameter "
                    f"{parameter}"
                )

                sqli_result = (
                    sqli_scanner.scan_get_parameter(
                        test_url,
                        parameter
                    )
                )

                for sqli_finding in (
                    sqli_result.get(
                        "findings",
                        []
                    )
                ):

                    finding = save_finding(
                        scan=scan,
                        vulnerability_type=sqli_finding["type"],
                        severity=sqli_finding["severity"],
                        url=sqli_finding["url"],
                        parameter=sqli_finding["parameter"],
                        evidence=sqli_finding["evidence"],
                        seen_findings=seen_findings,
                        confidence=sqli_finding.get("confidence")
                    )

                    if finding:
                        findings_count += 1

                        print(
                            f"[SQLi] Finding: "
                            f"{sqli_finding['type']} "
                            f"in form parameter: {parameter}"
                        )

        # ==================================================
        # 5. SECURITY HEADERS
        # ==================================================

        print(
            "[HEADERS] Scanning security headers"
        )
        
        scan.progress = 90
        scan.progress_status = "Scanning security headers..."
        db.session.commit()

        headers_result = headers_scanner.scan(
            target_url
        )

        for header_finding in (
            headers_result["findings"]
        ):

            finding = save_finding(
                scan=scan,
                vulnerability_type=header_finding["type"],
                severity=header_finding["severity"],
                url=target_url,
                parameter=None,
                evidence=header_finding["evidence"],
                seen_findings=seen_findings
            )

            if finding:
                findings_count += 1

                print(
                    f"[HEADERS] Finding: "
                    f"{header_finding['type']}"
                )

        # ==================================================
        # 6. ADDITIONAL SCANNERS
        # ==================================================
        scan.progress = 95
        scan.progress_status = "Scanning for directory listing and info disclosure..."
        db.session.commit()

        dir_result = dir_scanner.scan(target_url)
        for dir_finding in dir_result["findings"]:
            finding = save_finding(
                scan=scan,
                vulnerability_type=dir_finding["type"],
                severity=dir_finding["severity"],
                url=dir_finding["url"],
                parameter=None,
                evidence=dir_finding["evidence"],
                seen_findings=seen_findings,
                confidence=dir_finding["confidence"]
            )
            if finding:
                findings_count += 1
                print(f"[DIR] Finding: {dir_finding['type']}")

        info_result = info_scanner.scan(target_url)
        for info_finding in info_result["findings"]:
            finding = save_finding(
                scan=scan,
                vulnerability_type=info_finding["type"],
                severity=info_finding["severity"],
                url=info_finding["url"],
                parameter=None,
                evidence=info_finding["evidence"],
                seen_findings=seen_findings,
                confidence=info_finding["confidence"]
            )
            if finding:
                findings_count += 1
                print(f"[INFO] Finding: {info_finding['type']}")

        # ==================================================
        # 7. COMPLETE SCAN
        # ==================================================

        scan.status = "completed"
        scan.progress = 100
        scan.progress_status = "Scan completed successfully."

        scan.completed_at = datetime.utcnow()
        scan.requests_made = engine.requests_made
        scan.errors_count = engine.errors_count
        
        scan.pages_scanned = len(result.get("pages", []))
        scan.forms_discovered = len(result.get("forms", []))

        db.session.commit()

        print(
            f"[SCAN] Scan #{scan.id} completed"
        )

        print(
            f"[SCAN] Findings: "
            f"{findings_count}"
        )

        return {
            "scan_id": scan.id,
            "status": scan.status,
            "findings_count": findings_count
        }

    # ======================================================
    # 7. ERROR HANDLING
    # ======================================================

    except Exception as error:

        scan.status = "failed"
        scan.progress_status = f"Failed: {str(error)}"

        scan.completed_at = datetime.utcnow()
        
        if 'engine' in locals():
            scan.requests_made = engine.requests_made
            scan.errors_count = engine.errors_count

        db.session.commit()

        print(
            f"[SCAN ERROR] {error}"
        )

        raise