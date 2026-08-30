from __future__ import annotations

import re
from html import unescape
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .config import HTTPConfig
from .models import ContentObservation
from .screenshot_probe import has_only_public_addresses

Fetcher = Callable[[str, HTTPConfig], tuple[int | None, str, bytes]]


def extract_title(html: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", html, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return unescape(title)


def decode_html(raw: bytes, charset: str | None) -> str:
    candidates = [charset, "utf-8", "cp932", "shift_jis", "euc_jp"]
    decoded = []
    for candidate in candidates:
        if not candidate:
            continue
        try:
            text = raw.decode(candidate, errors="replace")
        except LookupError:
            continue
        decoded.append((text.count("\ufffd"), text))
    if not decoded:
        return raw.decode("utf-8", errors="replace")
    return min(decoded, key=lambda item: item[0])[1]


def html_to_text(html: str) -> str:
    without_scripts = re.sub(
        r"<(script|style)[^>]*>.*?</\1>",
        " ",
        html,
        flags=re.IGNORECASE | re.DOTALL,
    )
    text = re.sub(r"<[^>]+>", " ", without_scripts)
    return re.sub(r"\s+", " ", unescape(text)).strip()


def has_login_form(html: str) -> bool:
    forms = re.findall(r"<form\b.*?</form>", html, flags=re.IGNORECASE | re.DOTALL)
    for form in forms:
        lower = form.lower()
        if 'type="password"' in lower or "type='password'" in lower:
            return True
        if any(word in lower for word in ("login", "signin", "sign-in", "ログイン")):
            return True
    return False


def brand_terms_from_seed(seed_domain: str) -> tuple[str, ...]:
    labels = seed_domain.lower().split(".")
    if not labels:
        return ()
    first = labels[0]
    terms = {first}
    if first.startswith("ntt") or "docomo" in labels:
        terms.add("ntt")
    if "docomo" in labels:
        terms.add("docomo")
    return tuple(sorted(terms))


def _default_fetcher(url: str, config: HTTPConfig) -> tuple[int | None, str, bytes]:
    request = Request(url, headers={"User-Agent": config.user_agent})
    with urlopen(request, timeout=config.timeout_seconds) as response:
        charset = response.headers.get_content_charset() or "utf-8"
        body = response.read(config.max_html_bytes)
        return response.status, charset, body


class HTTPProbe:
    def __init__(self, config: HTTPConfig, fetcher: Fetcher | None = None) -> None:
        self.config = config
        self.fetcher = fetcher or _default_fetcher

    def lookup(self, domain: str, addresses: tuple[str, ...]) -> ContentObservation:
        if not has_only_public_addresses(addresses):
            return ContentObservation(domain=domain)

        for scheme in ("https", "http"):
            url = f"{scheme}://{domain}/"
            try:
                status_code, charset, raw = self.fetcher(url, self.config)
            except HTTPError as exc:
                raw = exc.read(self.config.max_html_bytes)
                charset = exc.headers.get_content_charset() or "utf-8"
                status_code = exc.code
            except (URLError, TimeoutError, OSError):
                continue

            html = decode_html(raw, charset)
            return ContentObservation(
                domain=domain,
                url=url,
                status_code=status_code,
                title=extract_title(html),
                text=html_to_text(html),
                html=html,
                has_login_form=has_login_form(html),
            )

        return ContentObservation(domain=domain)
