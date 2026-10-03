import time
from typing import Optional, Dict, Any

import requests

from .config import Config
from .logger import get_logger


class HttpClient:
    def __init__(self, config: Config):
        self.config = config
        self.log = get_logger(config.verbose)
        self.session = requests.Session()

    def _headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        h = {
            "User-Agent": self.config.user_agent,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "close",
        }
        if extra:
            h.update(extra)
        return h

    def get(self, url: str, *, headers: Optional[Dict[str, str]] = None,
            allow_redirects: Optional[bool] = None,
            timeout: Optional[int] = None) -> Optional[requests.Response]:
        attempt = 0
        while attempt <= self.config.max_retries:
            try:
                return self.session.get(
                    url,
                    headers=self._headers(headers),
                    allow_redirects=self.config.follow_redirects
                    if allow_redirects is None else allow_redirects,
                    timeout=timeout or self.config.timeout,
                    verify=self.config.verify_tls,
                    proxies=self.config.proxy_map(),
                )
            except requests.RequestException as e:
                attempt += 1
                self.log.debug(f"request error {url}: {e}")
                time.sleep(0.5 * attempt)
        return None

    def head(self, url: str, *, allow_redirects: bool = True,
             timeout: Optional[int] = None) -> Optional[requests.Response]:
        try:
            return self.session.head(
                url,
                headers=self._headers(),
                allow_redirects=allow_redirects,
                timeout=timeout or self.config.timeout,
                verify=self.config.verify_tls,
                proxies=self.config.proxy_map(),
            )
        except requests.RequestException:
            return None

    def close(self) -> None:
        try:
            self.session.close()
        except Exception:
            pass
