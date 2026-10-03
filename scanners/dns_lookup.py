from typing import Dict, List

try:
    import dns.resolver
    import dns.exception
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


class DnsScanner:
    RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "CAA"]

    def run(self, host: str) -> Dict:
        result = {"host": host, "records": {}, "error": None}
        if not HAS_DNS:
            result["error"] = "dnspython not installed"
            return result

        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        for rtype in self.RECORD_TYPES:
            try:
                answers = resolver.resolve(host, rtype)
                values = [str(r).strip() for r in answers]
                if values:
                    result["records"][rtype] = values
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.exception.Timeout, dns.resolver.NoNameservers):
                continue
            except Exception:
                continue
        return result