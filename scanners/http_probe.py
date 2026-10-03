from typing import Dict, List, Optional

from ..core.http import HttpClient
from ..core.utils import truncate


class HttpProbe:
    def __init__(self, client: HttpClient):
        self.client = client

    def run(self, url: str) -> Dict:
        result = {
            "url": url,
            "status_code": None,
            "reason": None,
            "headers": {},
            "redirects": [],
            "final_url": url,
            "content_length": None,
            "content_type": None,
            "server": None,
            "powered_by": None,
            "error": None,
        }

        response = self.client.get(url, allow_redirects=False)
        if response is None:
            result["error"] = "no response"
            return result

        chain = []
        current = response
        hops = 0
        while current is not None and current.is_redirect and hops < 10:
            location = current.headers.get("Location", "")
            chain.append({"from": current.url, "to": location,
                          "status": current.status_code})
            next_url = location
            if not next_url.startswith("http"):
                from urllib.parse import urljoin
                next_url = urljoin(current.url, next_url)
            current = self.client.get(next_url, allow_redirects=False)
            hops += 1

        if current is not None:
            result["status_code"] = current.status_code
            result["reason"] = current.reason
            result["final_url"] = current.url
            result["headers"] = {k: v for k, v in current.headers.items()}
            result["content_length"] = current.headers.get("Content-Length")
            result["content_type"] = current.headers.get("Content-Type")
            result["server"] = current.headers.get("Server")
            result["powered_by"] = current.headers.get("X-Powered-By")
            result["body_sample"] = truncate(current.text, 4000)

        result["redirects"] = chain
        return result
