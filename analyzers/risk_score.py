from typing import Dict, List


class RiskAnalyzer:
    def run(self, report: Dict) -> Dict:
        score = 100
        reasons: List[Dict] = []

        probe = report.get("http_probe", {})
        headers = report.get("security_headers", {})
        secrets = report.get("secrets", {})
        tech = report.get("tech", {})
        tls = report.get("tls", {})

        if not tls.get("enabled"):
            score -= 20
            reasons.append({"weight": -20, "reason": "HTTPS not enabled"})
        else:
            if tls.get("error"):
                score -= 15
                reasons.append({"weight": -15, "reason": f"TLS error: {tls.get('error')}"})
            days = tls.get("expires_in_days")
            if isinstance(days, int) and days < 14:
                score -= 10
                reasons.append({"weight": -10, "reason": f"TLS certificate expires in {days} days"})

        missing = headers.get("missing", [])
        for m in missing:
            sev = m.get("severity")
            if sev == "high":
                score -= 8
                reasons.append({"weight": -8, "reason": f"Missing header: {m['name']}"})
            elif sev == "medium":
                score -= 4
                reasons.append({"weight": -4, "reason": f"Missing header: {m['name']}"})
            elif sev == "low":
                score -= 2
                reasons.append({"weight": -2, "reason": f"Missing header: {m['name']}"})

        for w in headers.get("weak", []):
            score -= 3
            reasons.append({"weight": -3, "reason": f"Weak header: {w['name']} ({w['reason']})"})

        sev_counts = secrets.get("by_severity", {})
        for sev, weight in (("critical", 25), ("high", 12), ("medium", 5), ("low", 2)):
            count = sev_counts.get(sev, 0)
            if count:
                delta = weight * count
                score -= delta
                reasons.append({"weight": -delta,
                                "reason": f"{count} {sev} secret(s) detected"})

        if not tech.get("waf_detected"):
            score -= 5
            reasons.append({"weight": -5, "reason": "No WAF detected"})

        status = probe.get("status_code")
        if status is None:
            score -= 15
            reasons.append({"weight": -15, "reason": "No HTTP response"})

        score = max(0, min(100, score))
        grade = self._grade(score)

        return {
            "score": score,
            "grade": grade,
            "reasons": reasons,
        }

    def _grade(self, score: int) -> str:
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"
