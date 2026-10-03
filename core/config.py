import os
from dataclasses import dataclass, field
from typing import List


@dataclass
class Config:
    timeout: int = 15
    max_retries: int = 3
    user_agent: str = "Sentrys/1.0 (+https://localhost)"
    follow_redirects: bool = True
    verify_tls: bool = True
    proxy: str = ""
    output_dir: str = "reports"
    verbose: bool = False
    concurrency: int = 8

    def apply_env(self) -> "Config":
        self.proxy = os.environ.get("SENTRYS_PROXY", self.proxy)
        self.output_dir = os.environ.get("SENTRYS_OUTPUT", self.output_dir)
        return self

    def proxy_map(self):
        if not self.proxy:
            return None
        return {"http": self.proxy, "https": self.proxy}