import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

class ScannerEngine:
    def __init__(self, timeout=5, retries=2, rate_limit_delay=0.0):
        self.timeout = timeout
        self.rate_limit_delay = rate_limit_delay
        
        self.requests_made = 0
        self.errors_count = 0
        self.last_request_time = 0
        
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "SentinelScan-ScannerEngine/1.0"
        })
        
        # Configure Retries
        retry_strategy = Retry(
            total=retries,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"],
            backoff_factor=1
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def _wait_for_rate_limit(self):
        if self.rate_limit_delay > 0:
            elapsed = time.time() - self.last_request_time
            if elapsed < self.rate_limit_delay:
                time.sleep(self.rate_limit_delay - elapsed)

    def _track_request(self):
        self.requests_made += 1
        self.last_request_time = time.time()

    def get(self, url, **kwargs):
        self._wait_for_rate_limit()
        kwargs.setdefault('timeout', self.timeout)
        try:
            response = self.session.get(url, **kwargs)
            self._track_request()
            return response
        except requests.RequestException as e:
            self.errors_count += 1
            self._track_request()
            raise e

    def post(self, url, **kwargs):
        self._wait_for_rate_limit()
        kwargs.setdefault('timeout', self.timeout)
        try:
            response = self.session.post(url, **kwargs)
            self._track_request()
            return response
        except requests.RequestException as e:
            self.errors_count += 1
            self._track_request()
            raise e
