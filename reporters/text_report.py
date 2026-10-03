import os
from datetime import datetime, timezone
from typing import Dict, List


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class TextReporter:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def _line(self, char: str = "-", width: int = 72) -> str:
        return char * width

    def _section(self, title: str) -> List[str]:
        return ["", self._line("="), title, self._line("=")]

    def render(self, report: Dict) -> str:
        lines: List[str] = []
        target = report.get("target", {})
        meta = report.get("meta", {})
        risk = report.get("risk", {})
        probe = report.get("http_probe", {})
        tls = report.get("tls", {})
        headers = report.get("security_headers", {})
        tech = report.get("tech", {})
        secrets = report.get("secrets", {})
        robots = report.get("robots_sitemap", {})
        dns = report.get("dns", {})
        username = report.get("username_osint")

        lines.append(self._line("="))
        lines.append("SENTRYS REPORT")
        lines.append(self._line("="))
        lines.append(f"Target        : {target.get('input')}")
        lines.append(f"URL           : {target.get('url')}")
        lines.append(f"Host          : {target.get('host')}")
        lines.append(f"Scanned at    : {meta.get('scanned_at')}")
        lines.append(f"Version       : {meta.get('version')}")
        lines.append(f"Risk score    : {risk.get('score')} ({risk.get('grade')})")

        if username:
            lines += self._section("USERNAME OSINT")
            lines.append(f"Username      : {username.get('username')}")
            lines.append(f"Checked       : {username.get('checked')} platforms")
            lines.append(f"Found         : {username.get('found_count')}")
            lines.append("")
            for f in username.get("found", []):
                lines.append(f"  [+] {f.get('platform'):<14} {f.get('url')}")
            if not username.get("found"):
                lines.append("  (none)")

        lines += self._section("HTTP PROBE")
        lines.append(f"Status        : {probe.get('status_code')} {probe.get('reason') or ''}")
        lines.append(f"Final URL     : {probe.get('final_url')}")
        lines.append(f"Server        : {probe.get('server')}")
        lines.append(f"Powered by    : {probe.get('powered_by')}")
        lines.append(f"Content-Type  : {probe.get('content_type')}")
        lines.append(f"Content-Length: {probe.get('content_length')}")
        redirects = probe.get("redirects", [])
        if redirects:
            lines.append("Redirects     :")
            for r in redirects:
                lines.append(f"  {r.get('status')} -> {r.get('to')}")

        lines += self._section("TLS")
        if not tls.get("enabled"):
            lines.append("HTTPS not enabled")
        else:
            lines.append(f"Subject       : {tls.get('subject')}")
            lines.append(f"Issuer        : {tls.get('issuer')}")
            lines.append(f"Not before    : {tls.get('not_before')}")
            lines.append(f"Not after     : {tls.get('not_after')}")
            lines.append(f"Expires in    : {tls.get('expires_in_days')} days")
            lines.append(f"TLS version   : {tls.get('tls_version')}")
            lines.append(f"Cipher        : {tls.get('cipher')}")
            if tls.get("error"):
                lines.append(f"Error         : {tls.get('error')}")

        lines += self._section("TECHNOLOGIES")
        lines.append(f"WAF           : {', '.join(tech.get('waf_detected') or []) or 'none'}")
        lines.append(f"CDN           : {', '.join(tech.get('cdn_detected') or []) or 'none'}")
        lines.append("Detected      :")
        for t in tech.get("technologies", []):
            lines.append(f"  - {t}")
        if not tech.get("technologies"):
            lines.append("  (none)")

        lines += self._section("SECURITY HEADERS")
        lines.append(f"Grade         : {headers.get('grade')}")
        lines.append("Present       :")
        for h in headers.get("present", []):
            lines.append(f"  [+] {h.get('name')}: {h.get('value')}")
        if not headers.get("present"):
            lines.append("  (none)")
        lines.append("Missing       :")
        for h in headers.get("missing", []):
            lines.append(f"  [-] {h.get('name')} ({h.get('severity')})")
        if not headers.get("missing"):
            lines.append("  (none)")
        if headers.get("weak"):
            lines.append("Weak          :")
            for h in headers["weak"]:
                lines.append(f"  [!] {h.get('name')}: {h.get('reason')}")

        lines += self._section("SECRETS")
        lines.append(f"Total         : {secrets.get('count', 0)}")
        for sev, count in (secrets.get("by_severity") or {}).items():
            lines.append(f"{sev.capitalize():<14}: {count}")
        findings = secrets.get("findings", [])
        if findings:
            findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity"), 9))
            lines.append("")
            for f in findings:
                lines.append(f"  [{f.get('severity').upper():<8}] {f.get('type')} @ {f.get('source')}")
                lines.append(f"    value : {f.get('masked')}")
                lines.append(f"    context: {f.get('context')}")

        lines += self._section("ROBOTS / SITEMAP / SECURITY.TXT")
        r = robots.get("robots", {})
        s = robots.get("sitemap", {})
        st = robots.get("security_txt", {})
        lines.append(f"robots.txt     : {'found' if r.get('found') else 'not found'} ({r.get('disallow_count')} disallow)")
        for d in r.get("disallow", [])[:50]:
            lines.append(f"  - {d}")
        lines.append(f"sitemap.xml    : {'found' if s.get('found') else 'not found'} ({s.get('url_count')} urls)")
        for u in s.get("sample", [])[:20]:
            lines.append(f"  - {u}")
        lines.append(f"security.txt   : {'found' if st.get('found') else 'not found'}")

        lines += self._section("DNS")
        records = dns.get("records", {})
        if not records:
            lines.append("No records or DNS module unavailable")
        for rtype, values in records.items():
            lines.append(f"{rtype}:")
            for v in values:
                lines.append(f"  - {v}")

        lines += self._section("RISK REASONS")
        for r in risk.get("reasons", []):
            lines.append(f"  {r.get('weight'):>4} : {r.get('reason')}")
        if not risk.get("reasons"):
            lines.append("  (none)")

        lines.append("")
        lines.append(self._line("="))
        lines.append("END OF REPORT")
        lines.append(self._line("="))

        return "\n".join(lines)

    def write(self, report: Dict, name: str) -> str:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe = "".join(c if c.isalnum() or c in "-._" else "_" for c in name)
        path = os.path.join(self.output_dir, f"{safe}_{ts}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.render(report))
        return path