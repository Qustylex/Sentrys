import argparse
import sys
from datetime import datetime, timezone

from . import __version__
from .core.config import Config
from .core.http import HttpClient
from .core.logger import get_logger
from .core.utils import normalize_target, extract_host, safe_filename
from .scanners.http_probe import HttpProbe
from .scanners.tech_fingerprint import TechFingerprint
from .scanners.secret_scanner import SecretScanner
from .scanners.security_headers import SecurityHeadersScanner
from .scanners.robots_sitemap import RobotsSitemapScanner
from .scanners.dns_lookup import DnsScanner
from .scanners.tls_info import TlsScanner
from .scanners.username_osint import UsernameOsint
from .analyzers.risk_score import RiskAnalyzer
from .reporters.json_report import JsonReporter
from .reporters.text_report import TextReporter


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sentrys",
        description="Sentrys - terminal reconnaissance toolkit.",
    )
    p.add_argument("target", nargs="?", default=None,
                   help="URL or domain to scan. If omitted, prompts.")
    p.add_argument("-u", "--username", default=None,
                   help="Run username OSINT on the given handle.")
    p.add_argument("--username-only", action="store_true",
                   help="Only run username OSINT, skip URL scan.")
    p.add_argument("-o", "--output", default="reports",
                   help="Output directory (default: reports).")
    p.add_argument("--timeout", type=int, default=15,
                   help="HTTP timeout per request in seconds.")
    p.add_argument("--retries", type=int, default=3,
                   help="Max retries per request.")
    p.add_argument("--no-redirects", action="store_true",
                   help="Do not follow redirects on the main probe.")
    p.add_argument("--no-tls-verify", action="store_true",
                   help="Disable TLS certificate verification.")
    p.add_argument("--proxy", default="",
                   help="HTTP/HTTPS proxy URL.")
    p.add_argument("--concurrency", type=int, default=8,
                   help="Concurrent workers for username checks.")
    p.add_argument("--json-only", action="store_true",
                   help="Only emit JSON report.")
    p.add_argument("--text-only", action="store_true",
                   help="Only emit text report.")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Verbose logging.")
    p.add_argument("-V", "--version", action="store_true",
                   help="Print version and exit.")
    return p


def prompt_target() -> str:
    try:
        return input("Target: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return ""


def run(target: str, args, log) -> int:
    config = Config(
        timeout=args.timeout,
        max_retries=args.retries,
        follow_redirects=not args.no_redirects,
        verify_tls=not args.no_tls_verify,
        proxy=args.proxy,
        output_dir=args.output,
        verbose=args.verbose,
        concurrency=args.concurrency,
    ).apply_env()

    client = HttpClient(config)
    try:
        if target:
            url = normalize_target(target)
            host = extract_host(url)
        else:
            url = ""
            host = ""

        report = {
            "meta": {
                "tool": "Sentrys",
                "version": __version__,
                "scanned_at": datetime.now(timezone.utc).isoformat(),
            },
            "target": {
                "input": target,
                "url": url,
                "host": host,
            },
        }

        if url:
            log.info(f"HTTP probe: {url}")
            probe = HttpProbe(client).run(url)
            report["http_probe"] = probe

            log.info("TLS information")
            report["tls"] = TlsScanner().run(url, timeout=config.timeout)

            log.info("Technology fingerprinting")
            report["tech"] = TechFingerprint().run(probe, url)

            log.info("Security headers")
            report["security_headers"] = SecurityHeadersScanner().run(probe)

            log.info("Secret scanning")
            extra_texts = []
            robots_data = RobotsSitemapScanner(client).run(url)
            report["robots_sitemap"] = robots_data
            if robots_data.get("robots", {}).get("found"):
                extra_texts.append({
                    "source": "robots.txt",
                    "text": "\n".join(robots_data["robots"].get("disallow", [])),
                })
            if robots_data.get("security_txt", {}).get("found"):
                extra_texts.append({
                    "source": "security.txt",
                    "text": robots_data["security_txt"].get("content", ""),
                })
            report["secrets"] = SecretScanner().run(probe, extra_texts)

            log.info("DNS lookup")
            report["dns"] = DnsScanner().run(host)

        if args.username:
            log.info(f"Username OSINT: {args.username}")
            report["username_osint"] = UsernameOsint(
                client, concurrency=config.concurrency
            ).run(args.username)

        if url:
            log.info("Risk analysis")
            report["risk"] = RiskAnalyzer().run(report)
        else:
            report["risk"] = {"score": None, "grade": "N/A", "reasons": []}

        json_path = None
        text_path = None

        if not args.text_only:
            json_path = JsonReporter(config.output_dir).write(
                report, safe_filename(host or args.username or "report")
            )
            log.info(f"JSON report: {json_path}")

        if not args.json_only:
            text_path = TextReporter(config.output_dir).write(
                report, safe_filename(host or args.username or "report")
            )
            log.info(f"Text report: {text_path}")

        return 0
    finally:
        client.close()


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        print(f"Sentrys {__version__}")
        return 0

    if not args.target and not args.username:
        args.target = prompt_target()
        if not args.target:
            print("No target provided.")
            return 1

    if args.username_only and not args.username:
        print("--username-only requires --username.")
        return 1

    log = get_logger(args.verbose)
    return run(args.target, args, log)


if __name__ == "__main__":
    sys.exit(main())
