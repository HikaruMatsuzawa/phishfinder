from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import urlopen

RDAP_ENDPOINT = "https://rdap.org/domain/{domain}"
REGISTRATION_ACTIONS = {"registration", "domain registration"}

Fetcher = Callable[[str, float], bytes]


def _default_fetcher(url: str, timeout: float) -> bytes:
    with urlopen(url, timeout=timeout) as response:
        return response.read()


def parse_rdap_datetime(value: str) -> datetime | None:
    try:
        normalized = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def parse_registered_at(payload: dict[str, Any]) -> datetime | None:
    for event in payload.get("events", []):
        action = str(event.get("eventAction", "")).lower()
        if action not in REGISTRATION_ACTIONS:
            continue
        event_date = event.get("eventDate")
        if not isinstance(event_date, str):
            continue
        parsed = parse_rdap_datetime(event_date)
        if parsed is not None:
            return parsed
    return None


class RDAPProbe:
    def __init__(self, fetcher: Fetcher | None = None, timeout: float = 10.0) -> None:
        self.fetcher = fetcher or _default_fetcher
        self.timeout = timeout

    def lookup_registered_at(self, domain: str) -> datetime | None:
        url = RDAP_ENDPOINT.format(domain=quote(domain.strip().lower(), safe=".-"))
        try:
            raw = self.fetcher(url, self.timeout)
            payload = json.loads(raw.decode("utf-8"))
        except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError):
            return None

        if not isinstance(payload, dict):
            return None
        return parse_registered_at(payload)
