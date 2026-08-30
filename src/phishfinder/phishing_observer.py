from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import re
import socket
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .config import strip_json_comments
from .progress import progress_bar

LABEL_REVIEW = "\u78ba\u8a8d\u5bfe\u8c61"
LABEL_PHISHING_SUSPECTED = "\u30d5\u30a3\u30c3\u30b7\u30f3\u30b0\u7591\u3044"
LABEL_BRAND = "\u30d6\u30e9\u30f3\u30c9\u540d\u3042\u308a"
LABEL_FORM = "\u30d5\u30a9\u30fc\u30e0\u3042\u308a"
LABEL_FAILED = "\u53d6\u5f97\u5931\u6557"
LABEL_REFERENCE_SKIPPED = "\u6b63\u898f\u30b5\u30a4\u30c8\u9664\u5916"
LABEL_DEMO_SKIPPED = "\u30c7\u30e2\u30fb\u6a21\u5199\u9664\u5916"
LABEL_NO_CREDENTIAL_REQUEST = "\u8a8d\u8a3c\u60c5\u5831\u8981\u6c42\u306a\u3057"

DEMO_INDICATOR_TERMS = (
    "clone",
    "demo",
    "portfolio",
    "tutorial",
    "practice",
    "sample",
    "project",
    "homepage",
    "frontend",
    "ui",
)
PUBLIC_DEV_HOST_SUFFIXES = ("github.io", "vercel.app", "netlify.app")
INFORMATIONAL_SITE_TERMS = (
    "blog",
    "fan",
    "fansite",
    "community",
    "forum",
    "wiki",
    "news",
    "article",
)


@dataclass(frozen=True)
class FeedConfig:
    name: str
    url: str
    enabled: bool = True
    format: str = "text"
    url_column: str = "url"


@dataclass(frozen=True)
class UrlRecord:
    url: str
    source: str
    reported_target: str = ""
    verified: str = ""
    online: str = ""


@dataclass(frozen=True)
class PhishingObserverConfig:
    feeds: tuple[FeedConfig, ...]
    manual_urls_path: Path = Path("phishing_capture/manual_urls.txt")
    output_dir: Path = Path("reports/phishing_observation")
    max_urls: int = 10
    max_checked_urls: int = 100
    timeout_seconds: float = 12.0
    wait_after_load_ms: int = 2500
    wait_until_network_idle: bool = True
    wait_for_stable_body_ms: int = 1200
    javascript_enabled: bool = True
    save_html: bool = False
    capture_reference_sites: bool = False
    progress: bool = True
    require_verified_online: bool = True
    require_http_success: bool = True
    exclude_reference_hosts: bool = True
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126 Safari/537.36"
    )
    brand_terms: tuple[str, ...] = ()
    target_terms: tuple[str, ...] = ()
    reference_sites: dict[str, str] | None = None


def load_observer_config(path: Path) -> PhishingObserverConfig:
    raw = json.loads(strip_json_comments(path.read_text(encoding="utf-8-sig")))
    if not isinstance(raw, dict):
        raise ValueError("config must be a JSON object.")

    feed_items = raw.get("feeds", [])
    if not isinstance(feed_items, list):
        raise ValueError("feeds must be an array.")

    feeds: list[FeedConfig] = []
    for item in feed_items:
        if not isinstance(item, dict):
            raise ValueError("each feed must be a JSON object.")
        feeds.append(
            FeedConfig(
                name=str(item.get("name", "feed")),
                url=str(item["url"]),
                enabled=bool(item.get("enabled", True)),
                format=str(item.get("format", "text")),
                url_column=str(item.get("url_column", "url")),
            )
        )

    terms = _string_list(raw, "brand_terms")
    target_terms = _string_list(raw, "target_terms")
    reference_sites = raw.get("reference_sites", {})
    if not isinstance(reference_sites, dict):
        raise ValueError("reference_sites must be a JSON object.")

    defaults = PhishingObserverConfig(feeds=tuple(feeds))
    return PhishingObserverConfig(
        feeds=tuple(feeds),
        manual_urls_path=Path(str(raw.get("manual_urls_path", defaults.manual_urls_path))),
        output_dir=Path(str(raw.get("output_dir", defaults.output_dir))),
        max_urls=int(raw.get("max_urls", defaults.max_urls)),
        max_checked_urls=int(raw.get("max_checked_urls", defaults.max_checked_urls)),
        timeout_seconds=float(raw.get("timeout_seconds", defaults.timeout_seconds)),
        wait_after_load_ms=int(raw.get("wait_after_load_ms", defaults.wait_after_load_ms)),
        wait_until_network_idle=bool(
            raw.get("wait_until_network_idle", defaults.wait_until_network_idle)
        ),
        wait_for_stable_body_ms=int(
            raw.get("wait_for_stable_body_ms", defaults.wait_for_stable_body_ms)
        ),
        javascript_enabled=bool(raw.get("javascript_enabled", defaults.javascript_enabled)),
        save_html=bool(raw.get("save_html", defaults.save_html)),
        capture_reference_sites=bool(
            raw.get("capture_reference_sites", defaults.capture_reference_sites)
        ),
        progress=bool(raw.get("progress", defaults.progress)),
        require_verified_online=bool(
            raw.get("require_verified_online", defaults.require_verified_online)
        ),
        require_http_success=bool(raw.get("require_http_success", defaults.require_http_success)),
        exclude_reference_hosts=bool(
            raw.get("exclude_reference_hosts", defaults.exclude_reference_hosts)
        ),
        user_agent=str(raw.get("user_agent", defaults.user_agent)),
        brand_terms=tuple(term.lower() for term in terms),
        target_terms=tuple(term.lower() for term in target_terms),
        reference_sites={str(key).lower(): str(value) for key, value in reference_sites.items()},
    )


def _string_list(raw: dict[str, Any], key: str) -> list[str]:
    value = raw.get(key, [])
    if not isinstance(value, list):
        raise ValueError(f"{key} must be an array.")
    return [str(item) for item in value]


def normalize_url(url: str) -> str | None:
    stripped = url.strip().strip("\"'")
    if not stripped or stripped.startswith("#"):
        return None
    parsed = urlparse(stripped)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    if parsed.username or parsed.password:
        return None
    return stripped


def is_public_host(hostname: str) -> bool:
    try:
        address = ipaddress.ip_address(hostname)
        return _is_public_ip(address)
    except ValueError:
        pass

    try:
        results = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False

    addresses = {sockaddr[0] for _, _, _, _, sockaddr in results}
    if not addresses:
        return False
    return all(_is_public_ip(ipaddress.ip_address(address)) for address in addresses)


def _is_public_ip(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def safe_name(value: str, fallback: str = "site") -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_.-]+", "_", value).strip("._")
    return (cleaned or fallback)[:120]


def canonical_url_key(url: str) -> str:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower().strip(".")
    if host.startswith("www."):
        host = host[4:]
    path = re.sub(r"/+", "/", parsed.path or "/").rstrip("/") or "/"
    query = parsed.query.lower()
    return f"{host}{path}?{query}" if query else f"{host}{path}"


def url_text_tokens(url: str) -> set[str]:
    parsed = urlparse(url)
    text = " ".join([parsed.hostname or "", parsed.path or "", parsed.query or ""])
    return {
        token
        for token in re.split(r"[^a-z0-9]+", text.lower())
        if token
    }


def has_demo_intent(url: str) -> bool:
    if normalize_url(url) is None:
        tokens = {
            token
            for token in re.split(r"[^a-z0-9]+", url.lower())
            if token
        }
    else:
        tokens = url_text_tokens(url)
    return any(term in tokens for term in DEMO_INDICATOR_TERMS)


def is_public_dev_host(hostname: str) -> bool:
    host = hostname.lower().strip(".")
    return any(host == suffix or host.endswith(f".{suffix}") for suffix in PUBLIC_DEV_HOST_SUFFIXES)


def is_likely_informational_page(
    url: str,
    title: str,
    body_text: str,
    form_count: int,
    password_count: int,
) -> bool:
    if password_count > 0 or form_count > 0:
        return False
    text = " ".join([url, title, body_text[:5000]]).lower()
    return any(term in text for term in INFORMATIONAL_SITE_TERMS)


def should_reject_after_observation(row: dict[str, Any]) -> tuple[bool, str]:
    url = str(row.get("url") or "")
    final_url = str(row.get("final_url") or "")
    parsed = urlparse(final_url or url)
    host = parsed.hostname or ""
    form_count = int(row.get("form_count") or 0)
    password_count = int(row.get("password_input_count") or 0)
    input_count = int(row.get("input_count") or 0)

    if has_demo_intent(url) or has_demo_intent(final_url):
        return True, LABEL_DEMO_SKIPPED
    if row.get("is_likely_informational_page"):
        return True, LABEL_NO_CREDENTIAL_REQUEST
    if is_public_dev_host(host) and password_count == 0:
        return True, LABEL_DEMO_SKIPPED
    if input_count == 0 and not row.get("matched_brand_terms"):
        return True, LABEL_NO_CREDENTIAL_REQUEST
    return False, ""


def screenshot_base_name(index: int, url: str, final_url: str = "") -> str:
    parsed = urlparse(final_url or url)
    original = urlparse(url)
    host = safe_name(parsed.hostname or original.hostname or "unknown", fallback="unknown")
    path_hint = safe_name(parsed.path.strip("/") or "root", fallback="root")[:55]
    digest = hashlib.sha1(url.encode("utf-8")).hexdigest()[:10]
    prefix = f"{index:03d}" if index else "reference"
    if final_url and (parsed.hostname or "") != (original.hostname or ""):
        original_host = safe_name(original.hostname or "unknown", fallback="unknown")[:35]
        return f"{prefix}__{original_host}__to__{host}__{path_hint}__{digest}"[:170]
    return f"{prefix}__{host}__{path_hint}__{digest}"[:170]


def fetch_feed_records(feed: FeedConfig, timeout_seconds: float) -> list[UrlRecord]:
    if not feed.enabled:
        return []

    request = Request(feed.url, headers={"User-Agent": "phishfinder-observer/0.1"})
    with urlopen(request, timeout=timeout_seconds) as response:
        body = response.read().decode("utf-8", errors="replace")

    if feed.format == "csv":
        reader = csv.DictReader(body.splitlines())
        return [
            UrlRecord(
                url=row.get(feed.url_column) or "",
                source=feed.name,
                reported_target=row.get("target") or "",
                verified=row.get("verified") or "",
                online=row.get("online") or "",
            )
            for row in reader
        ]
    if feed.format == "text":
        return [UrlRecord(url=line, source=feed.name) for line in body.splitlines()]
    raise ValueError(f"unsupported feed format: {feed.format}")


def read_manual_records(path: Path) -> list[UrlRecord]:
    if not path.exists():
        return []
    return [
        UrlRecord(url=line, source="manual")
        for line in path.read_text(encoding="utf-8-sig").splitlines()
    ]


def collect_urls(config: PhishingObserverConfig) -> tuple[list[UrlRecord], list[str]]:
    candidates: list[UrlRecord] = []
    warnings: list[str] = []

    enabled_feeds = [feed for feed in config.feeds if feed.enabled]
    for feed in progress_bar(
        enabled_feeds,
        desc="\u30d5\u30a3\u30fc\u30c9\u53d6\u5f97",
        unit="\u4ef6",
        enabled=config.progress and bool(enabled_feeds),
    ):
        try:
            candidates.extend(fetch_feed_records(feed, config.timeout_seconds))
        except (OSError, URLError, TimeoutError, ValueError) as exc:
            warnings.append(f"{feed.name}: feed fetch failed: {exc}")

    candidates.extend(read_manual_records(config.manual_urls_path))

    records: list[UrlRecord] = []
    seen: set[str] = set()
    candidate_iterable = progress_bar(
        candidates,
        desc="URL\u5019\u88dc\u78ba\u8a8d",
        unit="\u4ef6",
        enabled=config.progress and bool(candidates),
    )
    for candidate in candidate_iterable:
        normalized = normalize_url(candidate.url)
        if normalized is None:
            continue
        key = canonical_url_key(normalized)
        if key in seen:
            warnings.append(f"{normalized}: skipped because it is a duplicate of an already queued URL.")
            continue
        if has_demo_intent(normalized):
            warnings.append(f"{normalized}: skipped because the URL looks like a demo, clone, or practice page.")
            continue
        candidate = UrlRecord(
            url=normalized,
            source=candidate.source,
            reported_target=candidate.reported_target or "",
            verified=candidate.verified or "",
            online=candidate.online or "",
        )
        if config.require_verified_online and not is_verified_online_or_unknown(candidate):
            continue
        if config.target_terms and not record_matches_target_terms(candidate, config.target_terms):
            continue
        parsed = urlparse(normalized)
        if parsed.hostname is None:
            continue
        if config.exclude_reference_hosts and is_reference_host(parsed.hostname, config):
            warnings.append(f"{normalized}: skipped because it is a configured reference site.")
            continue
        if not is_public_host(parsed.hostname):
            warnings.append(f"{normalized}: skipped because host did not resolve to public IPs.")
            continue
        seen.add(key)
        records.append(candidate)
        if len(records) >= config.max_checked_urls:
            break

    return records, warnings


def url_matches_target_terms(url: str, target_terms: tuple[str, ...]) -> bool:
    return text_matches_terms(url, target_terms)


def record_matches_target_terms(record: UrlRecord, target_terms: tuple[str, ...]) -> bool:
    return text_matches_terms(" ".join([record.url or "", record.reported_target or ""]), target_terms)


def text_matches_terms(text: str, target_terms: tuple[str, ...]) -> bool:
    lowered = text.lower()
    tokens = [token for token in re.split(r"[^a-z0-9\u3040-\u30ff\u3400-\u9fff]+", lowered) if token]
    token_set = set(tokens)
    for term in target_terms:
        normalized = term.lower().strip()
        if not normalized:
            continue
        term_tokens = [
            token
            for token in re.split(r"[^a-z0-9\u3040-\u30ff\u3400-\u9fff]+", normalized)
            if token
        ]
        if len(term_tokens) == 1 and term_tokens[0] in token_set:
            return True
        if len(term_tokens) > 1 and contains_token_sequence(tokens, term_tokens):
            return True
    return False


def contains_token_sequence(tokens: list[str], term_tokens: list[str]) -> bool:
    if not term_tokens or len(term_tokens) > len(tokens):
        return False
    width = len(term_tokens)
    return any(tokens[index : index + width] == term_tokens for index in range(len(tokens) - width + 1))


def is_verified_online_or_unknown(record: UrlRecord) -> bool:
    if not record.verified and not record.online:
        return True
    verified = record.verified.lower()
    online = record.online.lower()
    return verified in {"yes", "true", "1"} and online in {"yes", "true", "1"}


def is_reference_host(hostname: str, config: PhishingObserverConfig) -> bool:
    references = config.reference_sites or {}
    host = hostname.lower().strip(".")
    for url in references.values():
        parsed = urlparse(url)
        reference_host = (parsed.hostname or "").lower().strip(".")
        if reference_host and (host == reference_host or host.endswith(f".{reference_host}")):
            return True
    return False


def timestamped_output_dir(base_dir: Path) -> Path:
    return base_dir / datetime.now().strftime("%Y%m%d_%H%M%S")


def detect_brand_terms(text: str, terms: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(term for term in terms if text_matches_terms(text, (term,)))


def observe_urls(config: PhishingObserverConfig) -> Path:
    print("\u516c\u958b\u30d5\u30a3\u30c3\u30b7\u30f3\u30b0URL\u306e\u89b3\u5bdf\u3092\u958b\u59cb\u3057\u307e\u3059\u3002", flush=True)
    print("\u30d5\u30a3\u30fc\u30c9\u3068\u624b\u52d5URL\u304b\u3089\u5019\u88dc\u3092\u53ce\u96c6\u4e2d\u3067\u3059\u3002", flush=True)
    records, warnings = collect_urls(config)
    run_dir = timestamped_output_dir(config.output_dir)
    screenshot_dir = run_dir / "screenshots"
    html_dir = run_dir / "html"
    reference_dir = run_dir / "references"
    screenshot_dir.mkdir(parents=True, exist_ok=True)
    if config.save_html:
        html_dir.mkdir(parents=True, exist_ok=True)
    if config.capture_reference_sites:
        reference_dir.mkdir(parents=True, exist_ok=True)

    print(f"\u53d6\u5f97URL\u6570: {len(records)} \u4ef6")
    print(f"JavaScript: {'ON' if config.javascript_enabled else 'OFF'}")
    print(f"\u51fa\u529b\u5148: {run_dir}")
    if config.target_terms:
        print(f"\u30bf\u30fc\u30b2\u30c3\u30c8\u8a9e: {', '.join(config.target_terms)}")
    if warnings:
        print(f"\u6ce8\u610f: \u30d5\u30a3\u30fc\u30c9\u53d6\u5f97\u30fb\u9664\u5916\u306b\u95a2\u3059\u308b\u8b66\u544a\u304c {len(warnings)} \u4ef6\u3042\u308a\u307e\u3059\u3002")

    rows: list[dict[str, Any]] = []
    rejected_rows: list[dict[str, Any]] = []
    reference_rows: list[dict[str, Any]] = []
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError("playwright is required for screenshots.") from exc

    print("Playwright Chromium\u3092\u8d77\u52d5\u4e2d\u3067\u3059\u3002", flush=True)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            reference_rows: list[dict[str, Any]] = []
            if config.capture_reference_sites:
                reference_rows = capture_reference_sites(browser, config, reference_dir)
            record_iterable = progress_bar(
                records,
                desc="\u30b5\u30a4\u30c8\u89b3\u5bdf",
                unit="\u4ef6",
                enabled=config.progress and bool(records),
            )
            for index, record in enumerate(record_iterable, start=1):
                print(f"[{index}/{len(records)}] {record.url}")
                started = time.monotonic()
                row = _observe_one(browser, config, record.url, screenshot_dir, html_dir, index)
                row["source"] = record.source
                row["reported_target"] = record.reported_target
                row["verified"] = record.verified
                row["online"] = record.online
                row["elapsed_seconds"] = round(time.monotonic() - started, 2)
                should_reject, reject_label = should_reject_after_observation(row)
                has_successful_capture = row_is_http_success(row)
                if row.get("suggested_label") == LABEL_REFERENCE_SKIPPED:
                    row["review_priority"] = "skip"
                    rejected_rows.append(row)
                elif config.require_http_success and not has_successful_capture:
                    row["suggested_label"] = "\u751f\u5b58\u78ba\u8a8d\u5931\u6557"
                    row["review_priority"] = "skip"
                    rejected_rows.append(row)
                elif should_reject:
                    if row.get("screenshot_path"):
                        Path(str(row["screenshot_path"])).unlink(missing_ok=True)
                        row["screenshot_path"] = ""
                    row["suggested_label"] = reject_label
                    row["review_priority"] = "skip"
                    rejected_rows.append(row)
                else:
                    row["review_priority"] = "review"
                    rows.append(row)
                label = row.get("suggested_label", LABEL_REVIEW)
                status = row.get("status_code") or LABEL_FAILED
                priority = row.get("review_priority", "review")
                print(f"  -> {status} / {priority} / {label} / {row.get('title') or '(no title)'}")
                if len(rows) >= config.max_urls:
                    print(f"\u767a\u8868\u7528\u5019\u88dc\u304c {config.max_urls} \u4ef6\u96c6\u307e\u3063\u305f\u305f\u3081\u7d42\u4e86\u3057\u307e\u3059\u3002")
                    break
        finally:
            browser.close()

    if reference_rows:
        (run_dir / "reference_sites.json").write_text(
            json.dumps(reference_rows, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    write_outputs(run_dir, rows, warnings, rejected_rows)
    print_summary(rows, warnings, rejected_rows)
    return run_dir


def capture_reference_sites(
    browser: Any, config: PhishingObserverConfig, reference_dir: Path
) -> list[dict[str, Any]]:
    references = config.reference_sites or {}
    if not references:
        return []
    reference_dir.mkdir(parents=True, exist_ok=True)
    print(f"\u6b63\u898f\u30b5\u30a4\u30c8\u6bd4\u8f03\u7528\u30b9\u30af\u30b7\u30e7: {len(references)} \u4ef6")
    rows: list[dict[str, Any]] = []
    for name, url in progress_bar(
        list(references.items()),
        desc="\u6b63\u898f\u30b5\u30a4\u30c8\u64ae\u5f71",
        unit="\u4ef6",
        enabled=config.progress and bool(references),
    ):
        normalized = normalize_url(url)
        if normalized is None:
            rows.append({"name": name, "url": url, "screenshot_path": "", "error": "invalid URL"})
            continue
        row = _observe_one(
            browser,
            config,
            normalized,
            reference_dir,
            Path(),
            0,
            allow_reference_screenshot=True,
        )
        rows.append(
            {
                "name": name,
                "url": normalized,
                "title": row.get("title", ""),
                "screenshot_path": row.get("screenshot_path", ""),
                "error": row.get("error", ""),
            }
        )
    return rows


def _observe_one(
    browser: Any,
    config: PhishingObserverConfig,
    url: str,
    screenshot_dir: Path,
    html_dir: Path,
    index: int,
    allow_reference_screenshot: bool = False,
) -> dict[str, Any]:
    from playwright.sync_api import Error, TimeoutError as PlaywrightTimeoutError

    parsed = urlparse(url)
    host = parsed.hostname or "unknown"

    context = browser.new_context(
        java_script_enabled=config.javascript_enabled,
        accept_downloads=False,
        ignore_https_errors=True,
        user_agent=config.user_agent,
        viewport={"width": 1365, "height": 768},
        permissions=[],
    )
    page = context.new_page()
    page.set_default_timeout(config.timeout_seconds * 1000)
    page.on("download", lambda download: download.cancel())

    try:
        response = page.goto(url, wait_until="domcontentloaded", timeout=config.timeout_seconds * 1000)
        wait_for_page_ready(page, config)
        status_code = response.status if response is not None else None

        title = page.title()
        final_url = page.url
        final_host = urlparse(final_url).hostname or ""
        base_name = screenshot_base_name(index, url, final_url)
        screenshot_path = screenshot_dir / f"{base_name}.png"
        html_path = html_dir / f"{base_name}.html"
        body_text = page.locator("body").inner_text(timeout=1000)[:20_000]
        html = page.content()
        form_count = page.locator("form").count()
        password_count = page.locator("input[type='password']").count()
        input_count = page.locator("input").count()
        matched_terms = detect_brand_terms(" ".join([url, final_url, title, body_text]), config.brand_terms)
        is_likely_informational = is_likely_informational_page(
            final_url,
            title,
            body_text,
            form_count,
            password_count,
        )

        should_save_screenshot = should_save_observation_screenshot(
            status_code,
            final_url,
            config,
            allow_reference_screenshot=allow_reference_screenshot,
        )
        saved_screenshot_path = ""
        if should_save_screenshot:
            page.screenshot(path=str(screenshot_path), full_page=False)
            if is_blank_screenshot(screenshot_path):
                screenshot_path.unlink(missing_ok=True)
            else:
                saved_screenshot_path = str(screenshot_path)
        saved_html_path = ""
        if config.save_html and should_save_screenshot:
            html_path.write_text(html, encoding="utf-8")
            saved_html_path = str(html_path)

        return {
            "url": url,
            "final_url": final_url,
            "canonical_url_key": canonical_url_key(final_url),
            "host": host,
            "final_host": final_host,
            "status_code": status_code,
            "title": title,
            "form_count": form_count,
            "input_count": input_count,
            "password_input_count": password_count,
            "matched_brand_terms": ";".join(matched_terms),
            "is_likely_informational_page": is_likely_informational,
            "screenshot_path": saved_screenshot_path,
            "html_path": saved_html_path,
            "suggested_label": (
                suggest_label(form_count, password_count, matched_terms)
                if should_save_screenshot
                else LABEL_REFERENCE_SKIPPED
                if final_url_is_reference_site(final_url, config)
                else LABEL_FAILED
            ),
            "error": "",
        }
    except (Error, PlaywrightTimeoutError, OSError) as exc:
        return {
            "url": url,
            "final_url": page.url if not page.is_closed() else "",
            "canonical_url_key": canonical_url_key(url),
            "host": host,
            "final_host": urlparse(page.url).hostname if not page.is_closed() else "",
            "status_code": None,
            "title": "",
            "form_count": 0,
            "input_count": 0,
            "password_input_count": 0,
            "matched_brand_terms": "",
            "is_likely_informational_page": False,
            "screenshot_path": "",
            "html_path": "",
            "suggested_label": LABEL_FAILED,
            "error": str(exc)[:500],
        }
    finally:
        context.close()


def wait_for_page_ready(page: Any, config: PhishingObserverConfig) -> None:
    if config.wait_until_network_idle:
        try:
            page.wait_for_load_state("networkidle", timeout=config.timeout_seconds * 1000)
        except Exception:
            pass
    if config.wait_after_load_ms > 0:
        page.wait_for_timeout(config.wait_after_load_ms)
    if config.wait_for_stable_body_ms > 0:
        wait_for_stable_body(page, config.wait_for_stable_body_ms)


def wait_for_stable_body(page: Any, stable_ms: int) -> None:
    deadline = time.monotonic() + max(stable_ms, 1) / 1000 + 3
    previous = ""
    stable_since = time.monotonic()
    while time.monotonic() < deadline:
        try:
            current = page.locator("body").inner_text(timeout=500)
        except Exception:
            current = ""
        if current == previous:
            if (time.monotonic() - stable_since) * 1000 >= stable_ms:
                return
        else:
            previous = current
            stable_since = time.monotonic()
        page.wait_for_timeout(250)


def suggest_label(form_count: int, password_count: int, matched_terms: tuple[str, ...]) -> str:
    if password_count > 0 and matched_terms:
        return LABEL_PHISHING_SUSPECTED
    if form_count > 0 and matched_terms:
        return LABEL_REVIEW
    if matched_terms:
        return LABEL_BRAND
    if form_count > 0:
        return LABEL_FORM
    return LABEL_REVIEW


def should_save_observation_screenshot(
    status_code: Any,
    final_url: str,
    config: PhishingObserverConfig,
    *,
    allow_reference_screenshot: bool = False,
) -> bool:
    if config.require_http_success and not is_http_success_status(status_code):
        return False
    if normalize_url(final_url) is None:
        return False
    if (
        config.exclude_reference_hosts
        and not allow_reference_screenshot
        and final_url_is_reference_site(final_url, config)
    ):
        return False
    return True


def final_url_is_reference_site(final_url: str, config: PhishingObserverConfig) -> bool:
    parsed = urlparse(final_url)
    return bool(parsed.hostname and is_reference_host(parsed.hostname, config))


def write_outputs(
    run_dir: Path,
    rows: list[dict[str, Any]],
    warnings: list[str],
    rejected_rows: list[dict[str, Any]],
) -> None:
    json_path = run_dir / "observation_report.json"
    csv_path = run_dir / "review.csv"
    rejected_csv_path = run_dir / "rejected.csv"
    warning_path = run_dir / "warnings.txt"

    json_path.write_text(
        json.dumps(
            {"rows": rows, "rejected_rows": rejected_rows, "warnings": warnings},
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    if warnings:
        warning_path.write_text("\n".join(warnings), encoding="utf-8")

    fieldnames = [
        "url",
        "final_url",
        "canonical_url_key",
        "host",
        "final_host",
        "source",
        "reported_target",
        "verified",
        "online",
        "status_code",
        "title",
        "form_count",
        "input_count",
        "password_input_count",
        "matched_brand_terms",
        "is_likely_informational_page",
        "screenshot_path",
        "suggested_label",
        "review_priority",
        "human_label",
        "memo",
        "error",
    ]
    with csv_path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writable = dict(row)
            writable["human_label"] = ""
            writable["memo"] = ""
            writer.writerow(writable)
    with rejected_csv_path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rejected_rows:
            writable = dict(row)
            writable["human_label"] = ""
            writable["memo"] = ""
            writer.writerow(writable)


def print_summary(
    rows: list[dict[str, Any]], warnings: list[str], rejected_rows: list[dict[str, Any]]
) -> None:
    captured = sum(1 for row in rows if row.get("screenshot_path"))
    failed = sum(1 for row in rows if row.get("error"))
    password_pages = sum(1 for row in rows if int(row.get("password_input_count") or 0) > 0)
    brand_pages = sum(1 for row in rows if row.get("matched_brand_terms"))

    print("")
    print("\u89b3\u5bdf\u30b5\u30de\u30ea\u30fc")
    print(f"- \u767a\u8868\u7528\u5019\u88dc: {len(rows)} \u4ef6")
    print(f"- \u9664\u5916\u5019\u88dc: {len(rejected_rows)} \u4ef6")
    print(f"- \u30b9\u30af\u30ea\u30fc\u30f3\u30b7\u30e7\u30c3\u30c8\u53d6\u5f97: {captured} \u4ef6")
    print(f"- \u53d6\u5f97\u5931\u6557: {failed} \u4ef6")
    print(f"- \u30d1\u30b9\u30ef\u30fc\u30c9\u5165\u529b\u6b04\u3042\u308a: {password_pages} \u4ef6")
    print(f"- \u30d6\u30e9\u30f3\u30c9\u8a9e\u691c\u51fa: {brand_pages} \u4ef6")
    if warnings:
        print(f"- \u8b66\u544a: {len(warnings)} \u4ef6")


def row_is_http_success(row: dict[str, Any]) -> bool:
    status = row.get("status_code")
    final_url = str(row.get("final_url") or "")
    return (
        is_http_success_status(status)
        and normalize_url(final_url) is not None
        and bool(row.get("screenshot_path"))
    )


def is_http_success_status(status: Any) -> bool:
    try:
        status_int = int(status)
    except (TypeError, ValueError):
        return False
    return 200 <= status_int < 400


def is_blank_screenshot(path: Path) -> bool:
    try:
        from PIL import Image, ImageStat

        with Image.open(path) as image:
            small = image.convert("L").resize((32, 18))
            stat = ImageStat.Stat(small)
            extrema = small.getextrema()
        return (extrema[1] - extrema[0]) < 5 and (stat.stddev[0] if stat.stddev else 0) < 2
    except Exception:
        return False
