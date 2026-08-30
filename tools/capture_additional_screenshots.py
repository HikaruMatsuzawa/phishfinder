from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from phishfinder.config import ScreenshotConfig
from phishfinder.models import DNSRecordSet, DomainObservation, Score
from phishfinder.pipeline import RankedDomain
from phishfinder.screenshot_probe import ScreenshotProbe, has_only_public_addresses


PARKING_TERMS = (
    "parking",
    "for sale",
    "domain for sale",
    "hugedomains",
    "domain error",
    "パーキング",
    "お名前.com",
    "取得されています",
)
STRONG_TERMS = (
    "login",
    "account",
    "secure",
    "security",
    "verify",
    "id",
    "pay",
    "payment",
    "card",
    "mail",
    "mypage",
    "support",
)


@dataclass(frozen=True)
class Candidate:
    rank: int
    seed_domain: str
    domain: str
    domain_risk: int
    status_code: int | None
    title: str
    addresses: tuple[str, ...]


def load_report(path: Path) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def is_parking_like(row: dict) -> bool:
    http = row.get("http") or {}
    text = f"{http.get('title') or ''} {http.get('text_excerpt') or ''}".lower()
    return any(term.lower() in text for term in PARKING_TERMS)


def strength(row: dict) -> tuple[int, int, int, int]:
    http = row.get("http") or {}
    domain = row["domain"].lower()
    status_code = http.get("status_code")
    keyword_score = sum(1 for term in STRONG_TERMS if term in domain)
    status_score = 2 if status_code == 200 else 1 if status_code in {403, 530, None} else 0
    title_score = 1 if http.get("title") else 0
    return (row.get("domain_risk", 0), keyword_score, status_score, title_score)


def to_candidate(row: dict) -> Candidate:
    http = row.get("http") or {}
    addresses = tuple(row.get("dns", {}).get("addresses", []))
    return Candidate(
        rank=int(row["rank"]),
        seed_domain=str(row["seed_domain"]),
        domain=str(row["domain"]),
        domain_risk=int(row.get("domain_risk", 0)),
        status_code=http.get("status_code"),
        title=str(http.get("title") or ""),
        addresses=addresses,
    )


def choose_candidates(rows: list[dict], limit: int, per_seed: int) -> list[Candidate]:
    pool = [
        row
        for row in rows
        if not row.get("screenshot_path")
        and row.get("domain_risk", 0) >= 20
        and has_only_public_addresses(tuple(row.get("dns", {}).get("addresses", [])))
        and not is_parking_like(row)
    ]
    pool.sort(key=strength, reverse=True)

    selected: list[Candidate] = []
    seed_counts: dict[str, int] = {}
    for row in pool:
        seed = row["seed_domain"]
        if seed_counts.get(seed, 0) >= per_seed:
            continue
        selected.append(to_candidate(row))
        seed_counts[seed] = seed_counts.get(seed, 0) + 1
        if len(selected) >= limit:
            break
    return selected


def to_ranked(candidate: Candidate) -> RankedDomain:
    return RankedDomain(
        domain=candidate.domain,
        score=Score(candidate.domain_risk, ()),
        observation=DomainObservation(
            domain=candidate.domain,
            seed_domain=candidate.seed_domain,
            dns=DNSRecordSet(addresses=candidate.addresses),
        ),
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="既存レポートからスクリーンショット未取得候補だけを追加撮影します。"
    )
    parser.add_argument("--report", type=Path, default=ROOT / "reports" / "domain_report.json")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "reports" / "additional_screenshots",
    )
    parser.add_argument("--limit", type=int, default=40)
    parser.add_argument("--per-seed", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=10)
    args = parser.parse_args()

    rows = load_report(args.report)
    candidates = choose_candidates(rows, args.limit, args.per_seed)
    print(f"追加スクショ候補: {len(candidates)} 件")
    for candidate in candidates:
        print(
            f"  rank={candidate.rank} seed={candidate.seed_domain} "
            f"domain={candidate.domain} status={candidate.status_code} title={candidate.title[:50]}"
        )

    config = ScreenshotConfig(
        enabled=True,
        limit=len(candidates),
        output_dir=args.output_dir,
        timeout_seconds=args.timeout,
        javascript_enabled=True,
        include_seed=False,
    )
    captured = ScreenshotProbe(config).capture([to_ranked(candidate) for candidate in candidates])
    print(f"保存できた追加スクショ: {len(captured)} 件")
    for domain, path in captured.items():
        print(f"  {domain}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
