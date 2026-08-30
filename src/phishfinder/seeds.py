from __future__ import annotations

import csv
import io
from pathlib import Path
from urllib.request import Request, urlopen

from .variants import split_domain

TRANCO_ID_URL = "https://tranco-list.eu/top-1m-id"
TRANCO_DOWNLOAD_URL = "https://tranco-list.eu/download/{list_id}/{limit}"
USER_AGENT = "phishfinder-research-tool/0.1"


def normalize_seed_domain(value: str) -> str | None:
    domain = value.split("#", 1)[0].strip().lower().rstrip(".")
    if not domain:
        return None
    try:
        split_domain(domain)
    except ValueError:
        return None
    return domain


def parse_seed_lines(lines: list[str]) -> tuple[str, ...]:
    seeds: list[str] = []
    seen: set[str] = set()
    for line in lines:
        domain = normalize_seed_domain(line)
        if domain is None or domain in seen:
            continue
        seen.add(domain)
        seeds.append(domain)
    return tuple(seeds)


def read_seed_file(path: Path) -> tuple[str, ...]:
    if not path.exists():
        return ()
    return parse_seed_lines(path.read_text(encoding="utf-8").splitlines())


def write_seed_file(path: Path, domains: tuple[str, ...]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(domains) + "\n", encoding="utf-8")


def parse_tranco_csv(text: str, limit: int) -> tuple[str, ...]:
    domains: list[str] = []
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        if not row:
            continue
        candidate = row[1] if len(row) >= 2 and row[0].isdigit() else row[0]
        domain = normalize_seed_domain(candidate)
        if domain is None:
            continue
        domains.append(domain)
        if len(domains) >= limit:
            break
    return tuple(domains)


def fetch_text(url: str, timeout: float = 30.0) -> str:
    request = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8")


def download_tranco_seeds(limit: int) -> tuple[str, ...]:
    list_id = fetch_text(TRANCO_ID_URL).strip()
    text = fetch_text(TRANCO_DOWNLOAD_URL.format(list_id=list_id, limit=limit))
    return parse_tranco_csv(text, limit=limit)
