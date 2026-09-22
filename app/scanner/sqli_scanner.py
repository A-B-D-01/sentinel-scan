import time
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


class SQLiScanner:

    def __init__(self, engine, time_based_timeout=10):
        self.engine = engine
        self.time_based_timeout = time_based_timeout

    ERROR_SIGNATURES = {
        "MySQL": [
            "sql syntax",
            "mysql",
            "mysql_fetch",
            "mysqli"
        ],
        "PostgreSQL": [
            "postgresql",
            "pg_query"
        ],
        "SQLite": [
            "sqlite error",
            "sqlite3"
        ],
        "Oracle": [
            "ora-",
            "oracle"
        ],
        "SQL Server": [
            "odbc",
            "sqlstate"
        ],
        "Generic": [
            "pdoexception",
            "database error"
        ]
    }

    ERROR_TEST_VALUES = [
        "'",
        "\""
    ]

    BOOLEAN_TESTS = [
        {"true": "1 AND 1=1", "false": "1 AND 1=0"},
        {"true": "' OR '1'='1", "false": "' OR '1'='0"},
        {"true": "') OR ('1'='1", "false": "') OR ('1'='0"}
    ]

    TIME_BASED_TESTS = [
        "SLEEP(3)",          # MySQL
        "pg_sleep(3)",       # PostgreSQL
        "WAITFOR DELAY '0:0:3'" # SQL Server
    ]

    def _build_url(self, parsed, params, parameter, value):
        test_params = params.copy()
        test_params[parameter] = [value]
        test_query = urlencode(test_params, doseq=True)
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            test_query,
            parsed.fragment
        ))

    def scan_get_parameter(self, url, parameter):

        parsed = urlparse(url)

        params = parse_qs(
            parsed.query,
            keep_blank_values=True
        )

        findings = []

        # Baseline request for Boolean and Time-based comparison
        baseline_url = self._build_url(parsed, params, parameter, params.get(parameter, [""])[0])
        try:
            baseline_response = self.engine.get(baseline_url)
            baseline_text = baseline_response.text
        except requests.RequestException as error:
            return {
                "vulnerable": False,
                "error": str(error),
                "findings": []
            }

        # 1. Error-Based SQLi
        for test_value in self.ERROR_TEST_VALUES:
            test_url = self._build_url(parsed, params, parameter, test_value)
            try:
                response = self.engine.get(test_url)
                response_text = response.text.lower()
            except requests.RequestException:
                continue

            found_error = False
            for dbms, signatures in self.ERROR_SIGNATURES.items():
                for signature in signatures:
                    if signature in response_text:
                        findings.append({
                            "type": "Potential SQL Injection",
                            "severity": "High",
                            "confidence": "High",
                            "url": test_url,
                            "parameter": parameter,
                            "evidence": f"Error-Based ({dbms}): Database error signature detected '{signature}'."
                        })
                        found_error = True
                        break
                if found_error:
                    break

        # 2. Boolean-Based SQLi
        for test_case in self.BOOLEAN_TESTS:
            true_url = self._build_url(parsed, params, parameter, test_case["true"])
            false_url = self._build_url(parsed, params, parameter, test_case["false"])
            try:
                true_response = self.engine.get(true_url)
                false_response = self.engine.get(false_url)
            except requests.RequestException:
                continue

            # If true condition matches baseline, and false condition differs from baseline
            if true_response.text == baseline_text and false_response.text != baseline_text:
                findings.append({
                    "type": "Potential SQL Injection",
                    "severity": "High",
                    "confidence": "High",
                    "url": true_url,
                    "parameter": parameter,
                    "evidence": f"Boolean-Based: Response differs between true ({test_case['true']}) and false ({test_case['false']}) conditions."
                })
                break # Just record one Boolean finding

        # 3. Time-Based SQLi
        for test_value in self.TIME_BASED_TESTS:
            test_url = self._build_url(parsed, params, parameter, test_value)
            try:
                start_time = time.time()
                # Use longer timeout for time-based test
                self.engine.get(test_url, timeout=self.time_based_timeout)
                elapsed_time = time.time() - start_time
                
                if elapsed_time >= 3.0:
                    findings.append({
                        "type": "Potential SQL Injection",
                        "severity": "High",
                        "confidence": "Medium",
                        "url": test_url,
                        "parameter": parameter,
                        "evidence": f"Time-Based: Response delayed by {elapsed_time:.2f}s using payload '{test_value}'."
                    })
                    break # Just record one Time finding
            except requests.exceptions.Timeout:
                # If it strictly timed out, it might be due to sleep, but also could be network
                findings.append({
                    "type": "Potential SQL Injection",
                    "severity": "High",
                    "confidence": "Medium",
                    "url": test_url,
                    "parameter": parameter,
                    "evidence": f"Time-Based: Request timed out, possibly due to delay payload '{test_value}'."
                })
                break
            except requests.RequestException:
                continue

        return {
            "vulnerable": len(findings) > 0,
            "url": url,
            "parameter": parameter,
            "findings": findings
        }