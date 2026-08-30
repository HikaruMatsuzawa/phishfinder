from __future__ import annotations

import argparse
import csv
import json
import sys

from .pipeline import discover_existing_domains, rank_domains
from .dns_probe import DNSProbe
from .rdap_probe import RDAPProbe
from .report import ranked_domains_to_jsonable
from .tls_probe import TLSProbe
from .variants import generate_variants


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phishfinder")
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate = subparsers.add_parser("generate", help="類似ドメイン候補を生成します")
    generate.add_argument("seed_domain")
    generate.add_argument("--limit", type=int)

    scan = subparsers.add_parser("scan-dns", help="DNSで実在する候補を出力します")
    scan.add_argument("seed_domain")
    scan.add_argument("--limit", type=int)
    scan.add_argument("--rdap", action="store_true", help="RDAPの登録日を含めます")
    scan.add_argument("--tls", action="store_true", help="TLS証明書情報を含めます")
    scan.add_argument("--dns-details", action="store_true", help="MX/NSレコードも取得します")
    scan.add_argument("--format", choices=("csv", "json"), default="csv")

    return parser


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    args = build_parser().parse_args(argv)
    if args.command == "generate":
        variants = generate_variants(args.seed_domain)
        for variant in variants[: args.limit]:
            print(variant)
        return 0

    if args.command == "scan-dns":
        rdap_probe = RDAPProbe() if args.rdap else None
        tls_probe = TLSProbe() if args.tls else None
        dns_probe = DNSProbe(include_details=args.dns_details)
        observations = discover_existing_domains(
            args.seed_domain,
            dns_probe=dns_probe,
            rdap_probe=rdap_probe,
            tls_probe=tls_probe,
            limit=args.limit,
        )
        ranked = rank_domains(observations)
        if args.format == "json":
            json.dump(ranked_domains_to_jsonable(ranked), sys.stdout, indent=2, ensure_ascii=False)
            print()
            return 0

        writer = csv.writer(sys.stdout)
        writer.writerow(
            [
                "rank",
                "domain",
                "domain_risk",
                "registered_at",
                "reasons",
                "addresses",
                "mx_records",
                "name_servers",
                "https_available",
                "tls_not_before",
                "tls_not_after",
                "tls_issuer",
            ]
        )
        for index, item in enumerate(ranked, start=1):
            writer.writerow(
                [
                    index,
                    item.domain,
                    item.score.value,
                    item.observation.registered_at.isoformat()
                    if item.observation.registered_at
                    else "",
                    "; ".join(item.score.reasons),
                    " ".join(item.observation.dns.addresses),
                    " ".join(item.observation.dns.mx_records),
                    " ".join(item.observation.dns.name_servers),
                    item.observation.tls.https_available,
                    item.observation.tls.not_before.isoformat()
                    if item.observation.tls.not_before
                    else "",
                    item.observation.tls.not_after.isoformat()
                    if item.observation.tls.not_after
                    else "",
                    item.observation.tls.issuer or "",
                ]
            )
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
