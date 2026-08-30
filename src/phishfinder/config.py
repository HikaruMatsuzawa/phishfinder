from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ScreenshotConfig:
    enabled: bool = False
    limit: int = 20
    output_dir: Path = Path("reports/screenshots")
    timeout_seconds: float = 8.0
    javascript_enabled: bool = False
    include_seed: bool = True


@dataclass(frozen=True)
class HTTPConfig:
    enabled: bool = True
    limit: int = 30
    timeout_seconds: float = 5.0
    max_html_bytes: int = 200_000
    user_agent: str = "phishfinder-research-tool/0.1"


@dataclass(frozen=True)
class ReviewConfig:
    enabled: bool = True
    output_path: Path = Path("reports/review.csv")


@dataclass(frozen=True)
class AppConfig:
    seeds_path: Path = Path("data/seeds.txt")
    seed_limit: int | None = 3
    variant_limit: int | None = 50
    dns_details: bool = False
    rdap: bool = False
    tls: bool = False
    progress: bool = True
    output_format: str = "json"
    output_path: Path = Path("reports/domain_report.json")
    http: HTTPConfig = HTTPConfig()
    screenshots: ScreenshotConfig = ScreenshotConfig()
    review: ReviewConfig = ReviewConfig()


def _path(value: Any, default: Path) -> Path:
    if value is None:
        return default
    return Path(str(value))


def _optional_int(value: Any, default: int | None) -> int | None:
    if value is None:
        return default
    if isinstance(value, str) and value.lower() in {"none", "all", ""}:
        return None
    return int(value)


def strip_json_comments(text: str) -> str:
    result: list[str] = []
    in_string = False
    escaped = False
    index = 0

    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""

        if in_string:
            result.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue

        if char == '"':
            in_string = True
            result.append(char)
            index += 1
            continue

        if char == "/" and next_char == "/":
            while index < len(text) and text[index] not in "\r\n":
                index += 1
            continue

        result.append(char)
        index += 1

    return "".join(result)


def load_config(path: Path) -> AppConfig:
    if not path.exists():
        return AppConfig()

    raw = json.loads(strip_json_comments(path.read_text(encoding="utf-8-sig")))
    if not isinstance(raw, dict):
        raise ValueError("configはJSONオブジェクトである必要があります。")

    screenshot_raw = raw.get("screenshots", {})
    if not isinstance(screenshot_raw, dict):
        raise ValueError("screenshotsはJSONオブジェクトである必要があります。")
    http_raw = raw.get("http", {})
    if not isinstance(http_raw, dict):
        raise ValueError("httpはJSONオブジェクトである必要があります。")
    review_raw = raw.get("review", {})
    if not isinstance(review_raw, dict):
        raise ValueError("reviewはJSONオブジェクトである必要があります。")

    defaults = AppConfig()
    screenshot_defaults = ScreenshotConfig()
    screenshots = ScreenshotConfig(
        enabled=bool(screenshot_raw.get("enabled", screenshot_defaults.enabled)),
        limit=int(screenshot_raw.get("limit", screenshot_defaults.limit)),
        output_dir=_path(screenshot_raw.get("output_dir"), screenshot_defaults.output_dir),
        timeout_seconds=float(
            screenshot_raw.get("timeout_seconds", screenshot_defaults.timeout_seconds)
        ),
        javascript_enabled=bool(
            screenshot_raw.get("javascript_enabled", screenshot_defaults.javascript_enabled)
        ),
        include_seed=bool(screenshot_raw.get("include_seed", screenshot_defaults.include_seed)),
    )
    http_defaults = HTTPConfig()
    http = HTTPConfig(
        enabled=bool(http_raw.get("enabled", http_defaults.enabled)),
        limit=int(http_raw.get("limit", http_defaults.limit)),
        timeout_seconds=float(http_raw.get("timeout_seconds", http_defaults.timeout_seconds)),
        max_html_bytes=int(http_raw.get("max_html_bytes", http_defaults.max_html_bytes)),
        user_agent=str(http_raw.get("user_agent", http_defaults.user_agent)),
    )
    review_defaults = ReviewConfig()
    review = ReviewConfig(
        enabled=bool(review_raw.get("enabled", review_defaults.enabled)),
        output_path=_path(review_raw.get("output_path"), review_defaults.output_path),
    )

    output_format = str(raw.get("output_format", defaults.output_format))
    if output_format not in {"json", "csv"}:
        raise ValueError("output_formatはjsonまたはcsvを指定してください。")

    return AppConfig(
        seeds_path=_path(raw.get("seeds_path"), defaults.seeds_path),
        seed_limit=_optional_int(raw.get("seed_limit"), defaults.seed_limit),
        variant_limit=_optional_int(raw.get("variant_limit"), defaults.variant_limit),
        dns_details=bool(raw.get("dns_details", defaults.dns_details)),
        rdap=bool(raw.get("rdap", defaults.rdap)),
        tls=bool(raw.get("tls", defaults.tls)),
        progress=bool(raw.get("progress", defaults.progress)),
        output_format=output_format,
        output_path=_path(raw.get("output_path"), defaults.output_path),
        http=http,
        screenshots=screenshots,
        review=review,
    )
