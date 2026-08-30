from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Callable, Iterable
from pathlib import Path

from .dns_probe import DNSProbe
from .models import ContentResult, DomainObservation, Score, TLSInfo
from .rdap_probe import RDAPProbe
from .scoring import domain_risk
from .tls_probe import TLSProbe
from .variants import generate_variants


@dataclass(frozen=True)
class RankedDomain:
    domain: str
    score: Score
    observation: DomainObservation
    content: ContentResult | None = None
    screenshot_path: Path | None = None


def discover_existing_domains(
    seed_domain: str,
    dns_probe: DNSProbe | None = None,
    rdap_probe: RDAPProbe | None = None,
    tls_probe: TLSProbe | None = None,
    limit: int | None = None,
    candidates: list[str] | None = None,
    progress_factory: Callable[[Iterable[str]], Iterable[str]] | None = None,
) -> list[DomainObservation]:
    dns_probe = dns_probe or DNSProbe()
    observations: list[DomainObservation] = []
    candidate_list = candidates or generate_variants(seed_domain)
    if limit is not None:
        candidate_list = candidate_list[:limit]

    candidate_iterable = progress_factory(candidate_list) if progress_factory else candidate_list

    for candidate in candidate_iterable:
        dns = dns_probe.lookup(candidate)
        if dns.exists:
            registered_at = None
            if rdap_probe is not None:
                registered_at = rdap_probe.lookup_registered_at(candidate)
            tls = None
            if tls_probe is not None:
                tls = tls_probe.lookup(candidate)
            observations.append(
                DomainObservation(
                    candidate,
                    seed_domain,
                    dns=dns,
                    registered_at=registered_at,
                    tls=tls if tls is not None else TLSInfo(),
                )
            )
    return observations


def rank_domains(observations: list[DomainObservation]) -> list[RankedDomain]:
    ranked = [
        RankedDomain(observation.domain, domain_risk(observation), observation)
        for observation in observations
    ]
    return sorted(ranked, key=lambda item: (-item.score.value, item.domain))
