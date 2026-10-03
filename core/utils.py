import ipaddress
import re
from typing import Optional
from urllib.parse import urlparse


def normalize_target(target: str) -> str:
    target = target.strip()
    if not target:
        raise ValueError("empty target")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", target):
        target = "https://" + target
    return target


def extract_host(url: str) -> str:
    return urlparse(url).hostname or ""


def extract_scheme(url: str) -> str:
    return urlparse(url).scheme or ""


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def truncate(value: str, limit: int = 120) -> str:
    if value is None:
        return ""
    value = str(value)
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def mask_secret(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def safe_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._\-]+", "_", value)


def dedupe(items):
    seen = set()
    out = []
    for i in items:
        if i in seen:
            continue
        seen.add(i)
        out.append(i)
    return out