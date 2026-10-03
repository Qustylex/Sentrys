from typing import Dict, List

from ..data.tech_signatures import SECURITY_HEADERS


class SecurityHeadersScanner:
    def run(self, probe: Dict) -> Dict:
        headers = {k.lower(): v for k, v in (probe.get("headers") or {}).items()}
        present = []
        missing = []
        weak = []

        for spec in SECURITY_HEADERS:
            name = spec["name"]
            key = name.lower()
            value = headers.get(key)
            if value:
                present.append({"name": name, "value": value})
                if name == "Strict-Transport-Security":
                    if "max-age" not in value.lower():
                        weak.append({"name": name, "reason": "missing max-age"})
                if name == "Content-Security-Policy":
                    if "unsafe-inline" in value.lower() or "unsafe-eval" in value.lower():
                        weak.append({"name": name, "reason": "allows unsafe-inline or unsafe-eval"})
            else:
                missing.append({
                    "name": name,
                    "severity": spec["severity_if_missing"],
                    "recommendation": spec["recommendation"],
                })

        grade = self._grade(len(missing), len(weak))

        return {
            "present": present,
            "missing": missing,
            "weak": weak,
            "grade": grade,
        }

    def _grade(self, missing_count: int, weak_count: int) -> str:
        score = 100 - missing_count * 8 - weak_count * 5
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"