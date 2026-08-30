from __future__ import annotations

from difflib import SequenceMatcher
from urllib.error import URLError
from urllib.request import Request, urlopen

from .screenshot_probe import has_only_public_addresses, resolve_public_addresses


def favicon_similarity(left: bytes | None, right: bytes | None) -> float:
    if not left or not right:
        return 0.0
    if left == right:
        return 1.0
    return SequenceMatcher(None, left, right).ratio()


class FaviconProbe:
    def __init__(
        self,
        *,
        timeout_seconds: float = 5.0,
        user_agent: str = "phishfinder-research-tool/0.1",
        max_bytes: int = 65536,
        fetcher=urlopen,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.user_agent = user_agent
        self.max_bytes = max_bytes
        self.fetcher = fetcher

    def lookup(self, domain: str, addresses: tuple[str, ...] = ()) -> bytes | None:
        resolved = addresses or resolve_public_addresses(domain)
        if not has_only_public_addresses(resolved):
            return None

        for scheme in ("https", "http"):
            request = Request(
                f"{scheme}://{domain}/favicon.ico",
                headers={"User-Agent": self.user_agent},
            )
            try:
                with self.fetcher(request, timeout=self.timeout_seconds) as response:
                    payload = response.read(self.max_bytes)
            except (OSError, URLError, TimeoutError):
                continue
            if payload:
                return payload
        return None
