import re
from typing import Dict, List

from ..data.secret_patterns import PATTERNS
from ..core.utils import mask_secret, truncate


class SecretScanner:
    def __init__(self, max_findings: int = 200):
        self.max_findings = max_findings
        self.compiled = [(p["name"], re.compile(p["regex"]), p["severity"])
                         for p in PATTERNS]

    def _scan_text(self, text: str, source: str, findings: List[Dict]) -> None:
        if not text:
            return
        if len(findings) >= self.max_findings:
            return
        for name, regex, severity in self.compiled:
            for match in regex.finditer(text):
                value = match.group(0)
                snippet = text[max(0, match.start() - 40):match.end() + 40]
                findings.append({
                    "type": name,
                    "severity": severity,
                    "source": source,
                    "masked": mask_secret(value),
                    "context": truncate(snippet.replace("\n", " "), 200),
                })
                if len(findings) >= self.max_findings:
                    return

    def run(self, probe: Dict, extra_texts: List[Dict]) -> Dict:
        findings: List[Dict] = []

        body = probe.get("body_sample") or ""
        self._scan_text(body, "html_body", findings)

        for header, value in (probe.get("headers") or {}).items():
            self._scan_text(f"{header}: {value}", f"header:{header}", findings)

        for entry in extra_texts:
            self._scan_text(entry.get("text", ""), entry.get("source", "extra"), findings)

        seen = set()
        deduped = []
        for f in findings:
            key = (f["type"], f["masked"], f["source"])
            if key in seen:
                continue
            seen.add(key)
            deduped.append(f)

        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in deduped:
            by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1

        return {
            "count": len(deduped),
            "by_severity": by_severity,
            "findings": deduped,
        }