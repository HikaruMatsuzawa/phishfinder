from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Callable

from .models import TLSInfo

CertificateFetcher = Callable[[str, float], dict[str, Any]]


def parse_certificate_datetime(value: str) -> datetime | None:
    try:
        parsed = datetime.strptime(value, "%b %d %H:%M:%S %Y GMT")
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc)


def parse_issuer(certificate: dict[str, Any]) -> str | None:
    issuer = certificate.get("issuer")
    if not isinstance(issuer, tuple):
        return None

    parts: list[str] = []
    for group in issuer:
        for key, value in group:
            if key in {"organizationName", "commonName"}:
                parts.append(str(value))
    return ", ".join(parts) if parts else None


def _default_certificate_fetcher(domain: str, timeout: float) -> dict[str, Any]:
    context = ssl.create_default_context()
    with socket.create_connection((domain, 443), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as wrapped:
            return wrapped.getpeercert()


class TLSProbe:
    def __init__(
        self,
        certificate_fetcher: CertificateFetcher | None = None,
        timeout: float = 5.0,
    ) -> None:
        self.certificate_fetcher = certificate_fetcher or _default_certificate_fetcher
        self.timeout = timeout

    def lookup(self, domain: str) -> TLSInfo:
        try:
            certificate = self.certificate_fetcher(domain, self.timeout)
        except (ssl.SSLError, socket.timeout, TimeoutError, OSError):
            return TLSInfo()

        return TLSInfo(
            https_available=True,
            not_before=parse_certificate_datetime(str(certificate.get("notBefore", ""))),
            not_after=parse_certificate_datetime(str(certificate.get("notAfter", ""))),
            issuer=parse_issuer(certificate),
        )
