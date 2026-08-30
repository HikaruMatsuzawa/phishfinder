from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from .pipeline import RankedDomain


def _isoformat(value) -> str | None:
    return value.isoformat() if value is not None else None


def ranked_domains_to_jsonable(ranked_domains: list[RankedDomain]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for rank, item in enumerate(ranked_domains, start=1):
        observation = item.observation
        row: dict[str, Any] = {
            "rank": rank,
            "domain": item.domain,
            "seed_domain": observation.seed_domain,
            "domain_risk": item.score.value,
            "reasons": list(item.score.reasons),
            "registered_at": _isoformat(observation.registered_at),
            "dns": {
                "addresses": list(observation.dns.addresses),
                "mx_records": list(observation.dns.mx_records),
                "name_servers": list(observation.dns.name_servers),
            },
            "tls": {
                "https_available": observation.tls.https_available,
                "not_before": _isoformat(observation.tls.not_before),
                "not_after": _isoformat(observation.tls.not_after),
                "issuer": observation.tls.issuer,
            },
            "screenshot_path": item.screenshot_path.as_posix() if item.screenshot_path else None,
        }
        if item.content is not None:
            content = item.content.observation
            row["content_risk"] = item.content.score.value
            row["content_reasons"] = list(item.content.score.reasons)
            row["http"] = {
                "url": content.url,
                "status_code": content.status_code,
                "title": content.title,
                "has_login_form": content.has_login_form,
                "similarity": {
                    "html": round(content.html_similarity, 3),
                    "favicon": round(content.favicon_similarity, 3),
                    "screenshot": round(content.screenshot_similarity, 3),
                },
                "text_excerpt": content.text[:500],
                "html_bytes": len(content.html.encode("utf-8")),
            }
        rows.append(row)
    return rows


def write_review_csv(path: Path, ranked_domains: list[RankedDomain]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(
            [
                "rank",
                "seed_domain",
                "domain",
                "domain_risk",
                "content_risk",
                "http_status",
                "http_title",
                "has_login_form",
                "screenshot_path",
                "human_label",
                "label_choices",
                "memo",
            ]
        )
        for rank, item in enumerate(ranked_domains, start=1):
            content = item.content.observation if item.content else None
            writer.writerow(
                [
                    rank,
                    item.observation.seed_domain,
                    item.domain,
                    item.score.value,
                    item.content.score.value if item.content else "",
                    content.status_code if content else "",
                    content.title if content else "",
                    content.has_login_form if content else "",
                    item.screenshot_path.as_posix() if item.screenshot_path else "",
                    "未確認",
                    "確認対象 / 無関係 / パーキング / ブランド意識あり / フィッシング疑い",
                    "",
                ]
            )
