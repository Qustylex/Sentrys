from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

from ..core.http import HttpClient
from ..data.username_platforms import PLATFORMS


class UsernameOsint:
    def __init__(self, client: HttpClient, concurrency: int = 8):
        self.client = client
        self.concurrency = concurrency

    def _check(self, platform: Dict, username: str) -> Dict:
        url = platform["url"].format(u=username)
        result = {
            "platform": platform["name"],
            "url": url,
            "exists": None,
            "status": None,
        }
        response = self.client.get(url, allow_redirects=True)
        if response is None:
            result["exists"] = False
            return result

        result["status"] = response.status_code

        if platform["check"] == "status":
            if response.status_code in platform.get("success", []):
                result["exists"] = True
            elif response.status_code in platform.get("failure", []):
                result["exists"] = False
            else:
                result["exists"] = None
        elif platform["check"] == "body":
            body = response.text
            success_marker = platform.get("success_body")
            failure_marker = platform.get("failure_body")
            if failure_marker and failure_marker in body:
                result["exists"] = False
            elif success_marker and success_marker in body:
                result["exists"] = True
            else:
                result["exists"] = None
        return result

    def run(self, username: str) -> Dict:
        findings = []
        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            futures = [pool.submit(self._check, p, username) for p in PLATFORMS]
            for fut in as_completed(futures):
                try:
                    findings.append(fut.result())
                except Exception:
                    continue

        findings.sort(key=lambda x: x["platform"].lower())
        found = [f for f in findings if f["exists"] is True]
        not_found = [f for f in findings if f["exists"] is False]
        unknown = [f for f in findings if f["exists"] is None]

        return {
            "username": username,
            "checked": len(findings),
            "found_count": len(found),
            "not_found_count": len(not_found),
            "unknown_count": len(unknown),
            "found": found,
            "not_found": not_found,
            "unknown": unknown,
        }