from __future__ import annotations

import socket
import subprocess
from typing import Callable

from .models import DNSRecordSet

AddressResolver = Callable[[str], list[str]]
CommandRunner = Callable[..., subprocess.CompletedProcess[str]]


def _default_address_resolver(domain: str) -> list[str]:
    addresses: set[str] = set()
    results = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
    for family, _, _, _, sockaddr in results:
        if family in (socket.AF_INET, socket.AF_INET6):
            addresses.add(sockaddr[0])
    return sorted(addresses)


def parse_nslookup_records(output: str, record_type: str) -> tuple[str, ...]:
    values: set[str] = set()
    marker = "mail exchanger =" if record_type == "MX" else "nameserver ="

    for line in output.splitlines():
        lower = line.lower()
        if marker not in lower:
            continue
        value = line[lower.index(marker) + len(marker) :].strip().rstrip(".")
        if value:
            values.add(value)
    return tuple(sorted(values))


class DNSProbe:
    def __init__(
        self,
        address_resolver: AddressResolver | None = None,
        command_runner: CommandRunner | None = None,
        timeout: float = 1.0,
        include_details: bool = False,
    ) -> None:
        self.address_resolver = address_resolver or _default_address_resolver
        self.command_runner = command_runner or subprocess.run
        self.timeout = timeout
        self.include_details = include_details

    def lookup(self, domain: str) -> DNSRecordSet:
        try:
            addresses = tuple(self.address_resolver(domain))
        except socket.gaierror:
            return DNSRecordSet()

        if not addresses:
            return DNSRecordSet()

        if not self.include_details:
            return DNSRecordSet(addresses=tuple(sorted(set(addresses))))

        return DNSRecordSet(
            addresses=tuple(sorted(set(addresses))),
            mx_records=self._lookup_text_records(domain, "MX"),
            name_servers=self._lookup_text_records(domain, "NS"),
        )

    def _lookup_text_records(self, domain: str, record_type: str) -> tuple[str, ...]:
        try:
            result = self.command_runner(
                ["nslookup", f"-type={record_type}", domain],
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except (FileNotFoundError, subprocess.SubprocessError, OSError):
            return ()
        return parse_nslookup_records(result.stdout, record_type)
