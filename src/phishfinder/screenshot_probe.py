from __future__ import annotations

import ipaddress
import re
import socket
from pathlib import Path
from urllib.parse import urlparse

from .config import ScreenshotConfig
from .pipeline import RankedDomain


def has_only_public_addresses(addresses: tuple[str, ...]) -> bool:
    if not addresses:
        return False
    for address in addresses:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            return False
        if (
            parsed.is_private
            or parsed.is_loopback
            or parsed.is_link_local
            or parsed.is_multicast
            or parsed.is_reserved
            or parsed.is_unspecified
        ):
            return False
    return True


def safe_filename(domain: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "_", domain)[:180]


def seed_output_dir(base_dir: Path, seed_domain: str) -> Path:
    return base_dir / safe_filename(seed_domain)


def screenshot_targets(ranked_domains: list[RankedDomain], limit: int) -> list[RankedDomain]:
    targets: list[RankedDomain] = []
    for item in ranked_domains:
        if not has_only_public_addresses(item.observation.dns.addresses):
            continue
        targets.append(item)
        if len(targets) >= limit:
            break
    return targets


def is_safe_http_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def resolve_public_addresses(domain: str) -> tuple[str, ...]:
    try:
        results = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return ()
    addresses = sorted({sockaddr[0] for family, _, _, _, sockaddr in results for sockaddr in [sockaddr]})
    return tuple(addresses)


class ScreenshotProbe:
    def __init__(self, config: ScreenshotConfig) -> None:
        self.config = config

    def capture(self, ranked_domains: list[RankedDomain]) -> dict[str, Path]:
        targets = screenshot_targets(ranked_domains, self.config.limit)
        seed_domains = sorted({item.observation.seed_domain for item in ranked_domains})
        if not targets and not seed_domains:
            return {}

        try:
            from playwright.sync_api import Error, TimeoutError, sync_playwright
        except ImportError as exc:
            raise RuntimeError("スクリーンショット取得にはplaywrightが必要です。") from exc

        output_dir = self.config.output_dir
        output_dir.mkdir(parents=True, exist_ok=True)
        captured: dict[str, Path] = {}

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            try:
                if self.config.include_seed:
                    for seed_domain in seed_domains:
                        if not has_only_public_addresses(resolve_public_addresses(seed_domain)):
                            continue
                        path = self._capture_domain(
                            browser,
                            seed_domain,
                            seed_output_dir(output_dir, seed_domain) / "seed",
                        )
                        if path is not None:
                            captured[f"seed:{seed_domain}"] = path

                for item in targets:
                    path = self._capture_domain(
                        browser,
                        item.domain,
                        seed_output_dir(output_dir, item.observation.seed_domain) / "candidates",
                    )
                    if path is not None:
                        captured[item.domain] = path
            finally:
                browser.close()

        return captured

    def _capture_domain(self, browser, domain: str, output_dir: Path) -> Path | None:
        from playwright.sync_api import Error, TimeoutError

        context = browser.new_context(
            java_script_enabled=self.config.javascript_enabled,
            accept_downloads=False,
            viewport={"width": 1365, "height": 768},
        )
        page = context.new_page()
        page.set_default_timeout(self.config.timeout_seconds * 1000)
        try:
            return self._capture_one(page, domain, output_dir)
        except (Error, TimeoutError):
            return None
        finally:
            context.close()

    def _capture_one(self, page, domain: str, output_dir: Path) -> Path | None:
        output_dir.mkdir(parents=True, exist_ok=True)
        for scheme in ("https", "http"):
            url = f"{scheme}://{domain}/"
            if not is_safe_http_url(url):
                continue
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=self.config.timeout_seconds * 1000)
                output_path = output_dir / f"{safe_filename(domain)}.png"
                page.screenshot(path=str(output_path), full_page=False)
                return output_path
            except Exception:
                continue
        return None
