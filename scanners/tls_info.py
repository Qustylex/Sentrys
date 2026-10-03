import socket
import ssl
from datetime import datetime, timezone
from typing import Dict
from urllib.parse import urlparse


class TlsScanner:
    def run(self, url: str, timeout: int = 10) -> Dict:
        parsed = urlparse(url)
        if parsed.scheme != "https":
            return {"enabled": False, "reason": "not https"}

        host = parsed.hostname
        port = parsed.port or 443
        if not host:
            return {"enabled": False, "reason": "no host"}

        result = {
            "enabled": True,
            "host": host,
            "port": port,
            "subject": None,
            "issuer": None,
            "not_before": None,
            "not_after": None,
            "expires_in_days": None,
            "san": [],
            "tls_version": None,
            "cipher": None,
            "error": None,
        }

        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    result["tls_version"] = ssock.version()
                    cipher = ssock.cipher()
                    if cipher:
                        result["cipher"] = cipher[0]

                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    result["subject"] = subject.get("commonName")
                    result["issuer"] = issuer.get("organizationName") or issuer.get("commonName")
                    result["not_before"] = cert.get("notBefore")
                    result["not_after"] = cert.get("notAfter")
                    result["san"] = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]

                    try:
                        exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                        exp = exp.replace(tzinfo=timezone.utc)
                        delta = exp - datetime.now(timezone.utc)
                        result["expires_in_days"] = delta.days
                    except Exception:
                        pass
        except Exception as e:
            result["error"] = str(e)

        return result