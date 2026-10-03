from typing import Dict, List, Set

from ..data.tech_signatures import SERVER_SIGNATURES


class TechFingerprint:
    def run(self, probe: Dict, url: str) -> Dict:
        detected: Set[str] = set()
        evidence: Dict[str, List[str]] = {}

        headers = {k.lower(): v for k, v in (probe.get("headers") or {}).items()}
        body = (probe.get("body_sample") or "").lower()
        cookies_raw = headers.get("set-cookie", "")
        cookies = cookies_raw.lower()

        for sig in SERVER_SIGNATURES:
            where = sig["where"]
            key = sig["key"].lower()
            needle = sig["contains"].lower()
            name = sig["name"]

            hit = False
            if where == "header":
                value = headers.get(key, "")
                if key in headers and (not needle or needle in value.lower()):
                    hit = True
            elif where == "body":
                if needle and needle in body:
                    hit = True
            elif where == "cookie":
                if needle and needle in cookies:
                    hit = True

            if hit:
                detected.add(name)
                evidence.setdefault(name, [])
                marker = f"{where}:{key or needle}"
                if marker not in evidence[name]:
                    evidence[name].append(marker)

        waf_names = {"Cloudflare", "Akamai", "Fastly", "Sucuri", "Imperva Incapsula",
                     "F5 BIG-IP", "Barracuda", "Amazon CloudFront"}
        cdn_names = {"Cloudflare", "Akamai", "Fastly", "Amazon CloudFront",
                     "Vercel", "Netlify", "GitHub Pages", "Heroku"}

        return {
            "technologies": sorted(detected),
            "evidence": evidence,
            "waf_detected": sorted(detected & waf_names),
            "cdn_detected": sorted(detected & cdn_names),
        }