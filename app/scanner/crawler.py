
from urllib import response
from urllib.parse import urljoin, urlparse, urldefrag

import requests
from bs4 import BeautifulSoup


class WebCrawler:

    def __init__(self, start_url, engine, max_pages=20):

        self.start_url = start_url
        self.engine = engine
        self.max_pages = max_pages

        parsed = urlparse(start_url)

        self.allowed_origin = (
            parsed.scheme,
            parsed.hostname,
            parsed.port
        )

        self.visited = set()
        self.pages = []
        self.forms = []

    def is_same_origin(self, url):

        parsed = urlparse(url)

        origin = (
            parsed.scheme,
            parsed.hostname,
            parsed.port
        )

        return origin == self.allowed_origin

    def normalize_url(self, url):

        url, _ = urldefrag(url)

        return url.rstrip("/") or url

    def crawl(self):

        queue = [self.start_url]

        while queue and len(self.visited) < self.max_pages:

            current_url = queue.pop(0)

            current_url = self.normalize_url(current_url)

            if current_url in self.visited:
                continue

            if not self.is_same_origin(current_url):
                continue

            self.visited.add(current_url)

            try:

                response = self.engine.get(
                    current_url
                )

                print(
                    f"[CRAWLER] {current_url} "
                    f"-> {response.status_code}"
                )

            except requests.RequestException as error:

                print(
                    f"[ERROR] Failed to fetch {current_url}"
                )

                print(f"[ERROR] {error}")

                continue

            content_type = response.headers.get(
                "Content-Type",
                ""
            )

            if "text/html" not in content_type:
                continue

            soup = BeautifulSoup(
                response.text,
                "html.parser"
            )

            self.pages.append({
                "url": current_url,
                "status_code": response.status_code,
                "title": (
                    soup.title.get_text(strip=True)
                    if soup.title else ""
                )
            })

            self.extract_forms(
                soup,
                current_url
            )

            for link in soup.find_all("a", href=True):

                next_url = urljoin(
                    current_url,
                    link["href"]
                )

                next_url = self.normalize_url(next_url)

                if (
                    self.is_same_origin(next_url)
                    and next_url not in self.visited
                    and next_url not in queue
                ):

                    queue.append(next_url)

        return {
            "pages": self.pages,
            "forms": self.forms
        }

    def extract_forms(self, soup, page_url):

        for form in soup.find_all("form"):

            method = form.get(
                "method",
                "GET"
            ).upper()

            action = urljoin(
                page_url,
                form.get("action", "")
            )

            inputs = []

            for field in form.find_all(
                ["input", "textarea", "select"]
            ):

                name = field.get("name")

                if not name:
                    continue

                inputs.append({
                    "name": name,
                    "type": field.get(
                        "type",
                        field.name
                    )
                })

            self.forms.append({
                "page_url": page_url,
                "action": action,
                "method": method,
                "inputs": inputs
            })