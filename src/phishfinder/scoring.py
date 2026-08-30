from __future__ import annotations

from datetime import datetime, timezone
from difflib import SequenceMatcher

from .models import ContentObservation, DomainObservation, Score

SUSPICIOUS_KEYWORDS = ("login", "secure", "support", "account", "verify")


def similarity(left: str, right: str) -> float:
    return SequenceMatcher(None, left.lower(), right.lower()).ratio()


def _base_name(domain: str) -> str:
    labels = domain.lower().rstrip(".").split(".")
    return ".".join(labels[:-1]) if len(labels) > 1 else domain.lower()


def domain_risk(observation: DomainObservation, now: datetime | None = None) -> Score:
    now = now or datetime.now(timezone.utc)
    score = 0
    reasons: list[str] = []
    closeness = similarity(observation.domain, observation.seed_domain)
    candidate_name = _base_name(observation.domain)
    seed_name = _base_name(observation.seed_domain)

    if closeness >= 0.85 or seed_name in candidate_name.split("-"):
        score += 20
        reasons.append("正規ドメインと非常に似ている")
    elif closeness >= 0.7:
        score += 10
        reasons.append("正規ドメインと似ている")

    if observation.registered_at is not None:
        age_days = (now - observation.registered_at).days
        if age_days <= 30:
            score += 20
            reasons.append("登録から30日以内")
        elif age_days <= 180:
            score += 10
            reasons.append("登録から180日以内")

    if any(keyword in observation.domain for keyword in SUSPICIOUS_KEYWORDS):
        score += 10
        reasons.append("ログインや認証を連想させる単語を含む")

    if observation.dns.mx_records:
        score += 10
        reasons.append("MXレコードあり")

    if observation.tls.https_available:
        score += 5
        reasons.append("HTTPSが有効")

    return Score(min(score, 100), tuple(reasons))


def content_risk(observation: ContentObservation, brand_terms: tuple[str, ...]) -> Score:
    text = f"{observation.title}\n{observation.text}".lower()
    score = 0
    reasons: list[str] = []

    if any(term.lower() in text for term in brand_terms):
        score += 20
        reasons.append("ページ内にブランド名が存在")

    if observation.has_login_form:
        score += 20
        reasons.append("ログインフォームあり")

    if observation.html_similarity >= 0.8:
        score += 20
        reasons.append("HTML構造が正規サイトと類似")

    if observation.favicon_similarity >= 0.8:
        score += 15
        reasons.append("faviconが類似")

    if observation.screenshot_similarity >= 0.8:
        score += 30
        reasons.append("スクリーンショットが類似")

    return Score(min(score, 100), tuple(reasons))


def overall_risk(domain_score: Score, content_score: Score) -> int:
    return round(domain_score.value * 0.45 + content_score.value * 0.55)
