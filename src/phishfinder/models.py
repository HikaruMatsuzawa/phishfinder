from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass(frozen=True)
class DNSRecordSet:
    addresses: tuple[str, ...] = ()
    mx_records: tuple[str, ...] = ()
    name_servers: tuple[str, ...] = ()

    @property
    def exists(self) -> bool:
        return bool(self.addresses)


@dataclass(frozen=True)
class TLSInfo:
    https_available: bool = False
    not_before: datetime | None = None
    not_after: datetime | None = None
    issuer: str | None = None


@dataclass(frozen=True)
class DomainObservation:
    domain: str
    seed_domain: str
    dns: DNSRecordSet = field(default_factory=DNSRecordSet)
    registered_at: datetime | None = None
    tls: TLSInfo = field(default_factory=TLSInfo)


@dataclass(frozen=True)
class ContentObservation:
    domain: str
    url: str | None = None
    status_code: int | None = None
    title: str = ""
    text: str = ""
    html: str = ""
    has_login_form: bool = False
    html_similarity: float = 0.0
    favicon_similarity: float = 0.0
    screenshot_similarity: float = 0.0


@dataclass(frozen=True)
class Score:
    value: int
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class ContentResult:
    observation: ContentObservation
    score: Score


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
