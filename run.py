from __future__ import annotations

import argparse
import csv
import json
import sys
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from phishfinder.config import AppConfig, load_config
from phishfinder.dns_probe import DNSProbe
from phishfinder.http_probe import HTTPProbe, brand_terms_from_seed
from phishfinder.models import ContentResult
from phishfinder.pipeline import discover_existing_domains, rank_domains
from phishfinder.progress import progress_bar
from phishfinder.rdap_probe import RDAPProbe
from phishfinder.report import ranked_domains_to_jsonable, write_review_csv
from phishfinder.seeds import download_tranco_seeds, read_seed_file, write_seed_file
from phishfinder.screenshot_probe import ScreenshotProbe
from phishfinder.scoring import content_risk
from phishfinder.tls_probe import TLSProbe
from phishfinder.variants import generate_variants

DEFAULT_SEEDS = ROOT / "data" / "seeds.txt"
DEFAULT_REPORT = ROOT / "reports" / "domain_report.json"
DEFAULT_CONFIG = ROOT / "config.json"


def configure_text_output() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="保存済みseedから、なりすまし候補の生成・DNS確認・レポート保存を一括実行します。"
    )
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG, help="設定ファイルのパスです。")
    subparsers = parser.add_subparsers(dest="command")

    import_seeds = subparsers.add_parser(
        "import-seeds",
        help="Trancoの公開ランキングからseedドメインを保存します。",
    )
    import_seeds.add_argument("--limit", type=int, default=100)
    import_seeds.add_argument("--output", type=Path, default=DEFAULT_SEEDS)

    subparsers.add_parser("test", help="テストを実行します。")

    parser.add_argument("--seeds", type=Path)
    parser.add_argument("--seed-limit", type=int)
    parser.add_argument("--variant-limit", type=int)
    parser.add_argument("--dns-details", action="store_true", help="MX/NSレコードも取得します。")
    parser.add_argument("--rdap", action="store_true", help="RDAPの登録日も取得します。")
    parser.add_argument("--tls", action="store_true", help="TLS証明書情報も取得します。")
    parser.add_argument("--no-progress", action="store_true", help="進捗バーを表示しません。")
    parser.add_argument("--format", choices=("json", "csv"))
    parser.add_argument("--output", type=Path)
    return parser


def import_seeds(limit: int, output: Path) -> int:
    domains = download_tranco_seeds(limit)
    write_seed_file(output, domains)
    print(f"{output} に {len(domains)} 件のseedを保存しました。")
    return 0


def run_tests() -> int:
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


def write_report(path: Path, output_format: str, ranked) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    if output_format == "json":
        path.write_text(
            json.dumps(ranked_domains_to_jsonable(ranked), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8-sig",
        )
        return

    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(
            [
                "rank",
                "seed_domain",
                "domain",
                "domain_risk",
                "content_risk",
                "reasons",
                "content_reasons",
                "http_status",
                "http_title",
                "has_login_form",
            ]
        )
        for rank, item in enumerate(ranked, start=1):
            writer.writerow(
                [
                    rank,
                    item.observation.seed_domain,
                    item.domain,
                    item.score.value,
                    item.content.score.value if item.content else "",
                    "; ".join(item.score.reasons),
                    "; ".join(item.content.score.reasons) if item.content else "",
                    item.content.observation.status_code if item.content else "",
                    item.content.observation.title if item.content else "",
                    item.content.observation.has_login_form if item.content else "",
                ]
            )


def attach_screenshot_paths(ranked, captured: dict[str, Path]):
    enriched = []
    for item in ranked:
        screenshot_path = captured.get(item.domain)
        if screenshot_path is not None:
            try:
                screenshot_path = screenshot_path.relative_to(ROOT)
            except ValueError:
                pass
        enriched.append(
            type(item)(
                domain=item.domain,
                score=item.score,
                observation=item.observation,
                content=item.content,
                screenshot_path=screenshot_path,
            )
        )
    return enriched


def resolve_screenshot_config(config):
    return type(config)(
        enabled=config.enabled,
        limit=config.limit,
        output_dir=resolve_path(config.output_dir),
        timeout_seconds=config.timeout_seconds,
        javascript_enabled=config.javascript_enabled,
        include_seed=config.include_seed,
    )


def enrich_with_http_metadata(config: AppConfig, ranked):
    if not config.http.enabled:
        return ranked

    probe = HTTPProbe(config.http)
    enriched = list(ranked)
    target_count = min(config.http.limit, len(enriched))
    print(f"[http] 上位 {target_count} 件のHTTPメタデータを取得中...")
    for index, item in enumerate(enriched[:target_count]):
        observation = probe.lookup(item.domain, item.observation.dns.addresses)
        score = content_risk(observation, brand_terms_from_seed(item.observation.seed_domain))
        enriched[index] = type(item)(
            domain=item.domain,
            score=item.score,
            observation=item.observation,
            content=ContentResult(observation=observation, score=score),
        )
    return enriched


def resolve_path(path: Path) -> Path:
    if path.is_absolute():
        return path
    return ROOT / path


def display_path(path: Path) -> str:
    resolved = resolve_path(path)
    try:
        return resolved.relative_to(ROOT).as_posix()
    except ValueError:
        return str(resolved)


def apply_cli_overrides(config: AppConfig, args: argparse.Namespace) -> AppConfig:
    updates: dict[str, Any] = {}
    if args.seeds is not None:
        updates["seeds_path"] = args.seeds
    if args.seed_limit is not None:
        updates["seed_limit"] = args.seed_limit
    if args.variant_limit is not None:
        updates["variant_limit"] = args.variant_limit
    if args.dns_details:
        updates["dns_details"] = True
    if args.rdap:
        updates["rdap"] = True
    if args.tls:
        updates["tls"] = True
    if args.no_progress:
        updates["progress"] = False
    if args.format is not None:
        updates["output_format"] = args.format
    if args.output is not None:
        updates["output_path"] = args.output
    return AppConfig(
        seeds_path=updates.get("seeds_path", config.seeds_path),
        seed_limit=updates.get("seed_limit", config.seed_limit),
        variant_limit=updates.get("variant_limit", config.variant_limit),
        dns_details=updates.get("dns_details", config.dns_details),
        rdap=updates.get("rdap", config.rdap),
        tls=updates.get("tls", config.tls),
        progress=updates.get("progress", config.progress),
        output_format=updates.get("output_format", config.output_format),
        output_path=updates.get("output_path", config.output_path),
        http=config.http,
        screenshots=config.screenshots,
        review=config.review,
    )


def scan_from_config(config: AppConfig) -> int:
    seeds = read_seed_file(resolve_path(config.seeds_path))
    if config.seed_limit is not None:
        seeds = seeds[: config.seed_limit]
    if not seeds:
        print("seedがありません。先に `python run.py import-seeds --limit 100` を実行してください。")
        return 1

    print_scan_settings(config, len(seeds))

    dns_probe = DNSProbe(include_details=config.dns_details)
    rdap_probe = RDAPProbe() if config.rdap else None
    tls_probe = TLSProbe() if config.tls else None
    all_observations = []
    total_candidates = 0

    for seed in seeds:
        candidates = generate_variants(seed)
        if config.variant_limit is not None:
            candidates = candidates[: config.variant_limit]
        total_candidates += len(candidates)

        print(f"[scan] {seed}: {len(candidates)} 件の候補をDNS確認中...")
        observations = discover_existing_domains(
            seed,
            dns_probe=dns_probe,
            rdap_probe=rdap_probe,
            tls_probe=tls_probe,
            limit=config.variant_limit,
            candidates=candidates,
            progress_factory=lambda items, seed=seed: progress_bar(
                items,
                desc=f"DNS {seed}",
                enabled=config.progress,
            ),
        )
        all_observations.extend(observations)
        print(f"[scan] {seed}: {len(candidates)} 件中 {len(observations)} 件が実在しました。")

    ranked = rank_domains(all_observations)
    ranked = enrich_with_http_metadata(config, ranked)

    if config.screenshots.enabled:
        screenshot_config = resolve_screenshot_config(config.screenshots)
        captured = ScreenshotProbe(screenshot_config).capture(ranked)
        ranked = attach_screenshot_paths(ranked, captured)
        candidate_count = len([key for key in captured if not key.startswith("seed:")])
        seed_count = len(captured) - candidate_count
        print(f"スクリーンショット: seed {seed_count} 件、候補 {candidate_count} 件を保存しました。")

    write_report(resolve_path(config.output_path), config.output_format, ranked)
    if config.review.enabled:
        write_review_csv(resolve_path(config.review.output_path), ranked)

    print(f"合計: seed {len(seeds)} 件、候補 {total_candidates} 件、実在候補 {len(ranked)} 件")
    print(f"レポート: {display_path(config.output_path)}")
    if config.review.enabled:
        print(f"レビューCSV: {display_path(config.review.output_path)}")
    print_top_results(ranked)
    return 0


def print_scan_settings(config: AppConfig, seed_count: int) -> None:
    print("実行設定:")
    print(f"  seedファイル: {display_path(config.seeds_path)}")
    print(f"  使用seed数: {seed_count}")
    print(f"  1 seedあたりの最大候補数: {config.variant_limit if config.variant_limit is not None else '全件'}")
    print(f"  DNS詳細(MX/NS): {'有効' if config.dns_details else '無効'}")
    print(f"  RDAP: {'有効' if config.rdap else '無効'}")
    print(f"  TLS: {'有効' if config.tls else '無効'}")
    print(f"  HTTPメタデータ: {'有効' if config.http.enabled else '無効'}")
    if config.http.enabled:
        print(f"  HTTP対象: 上位 {config.http.limit} 件")
    print(f"  スクリーンショット: {'有効' if config.screenshots.enabled else '無効'}")
    if config.screenshots.enabled:
        print(f"  スクリーンショット対象: 上位 {config.screenshots.limit} 件")
        print(f"  seedスクリーンショット: {'保存する' if config.screenshots.include_seed else '保存しない'}")
    print("")


def print_top_results(ranked, limit: int = 10) -> None:
    if not ranked:
        print("上位候補: なし")
        return

    print("上位候補:")
    for item in ranked[:limit]:
        content_score = item.content.score.value if item.content else "-"
        status = item.content.observation.status_code if item.content else "-"
        title = item.content.observation.title if item.content else ""
        print(
            f"  {item.domain} | seed={item.observation.seed_domain} "
            f"| domain={item.score.value} | content={content_score} | status={status} | title={title[:60]}"
        )


def main(argv: list[str] | None = None) -> int:
    configure_text_output()
    args = build_parser().parse_args(argv)
    if args.command == "import-seeds":
        return import_seeds(args.limit, args.output)
    if args.command == "test":
        return run_tests()
    config = apply_cli_overrides(load_config(args.config), args)
    return scan_from_config(config)


if __name__ == "__main__":
    raise SystemExit(main())
