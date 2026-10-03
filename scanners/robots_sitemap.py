from typing import Dict, List
from urllib.parse import urljoin, urlparse

from ..core.http import HttpClient


class RobotsSitemapScanner:
    def __init__(self, client: HttpClient):
        self.client = client

    def _fetch(self, url: str) -> Dict:
        response = self.client.get(url, allow_redirects=True)
        if response is None:
            return {"url": url, "found": False}
        return {
            "url": url,
            "found": response.status_code == 200,
            "status_code": response.status_code,
            "content": response.text[:20000] if response.status_code == 200 else "",
        }

    def run(self, base_url: str) -> Dict:
        parsed = urlparse(base_url)
        root = f"{parsed.scheme}://{parsed.netloc}"

        robots = self._fetch(urljoin(root, "/robots.txt"))
        sitemap = self._fetch(urljoin(root, "/sitemap.xml"))
        security = self._fetch(urljoin(root, "/.well-known/security.txt"))

        disallow = []
        if robots.get("found"):
            for line in robots["content"].splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        disallow.append(path)

        sitemap_urls = []
        if sitemap.get("found"):
            import re
            sitemap_urls = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", sitemap["content"])
            sitemap_urls = sitemap_urls[:200]

        return {
            "robots": {
                "found": robots.get("found", False),
                "url": robots["url"],
                "disallow_count": len(disallow),
                "disallow": disallow[:200],
            },
            "sitemap": {
                "found": sitemap.get("found", False),
                "url": sitemap["url"],
                "url_count": len(sitemap_urls),
                "sample": sitemap_urls[:50],
            },
            "security_txt": {
                "found": security.get("found", False),
                "url": security["url"],
                "content": security.get("content", "")[:5000],
            },
        }