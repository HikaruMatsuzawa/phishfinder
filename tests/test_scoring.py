import unittest
from datetime import datetime, timedelta, timezone

from phishfinder.models import ContentObservation, DNSRecordSet, DomainObservation, TLSInfo
from phishfinder.scoring import content_risk, domain_risk, overall_risk


class ScoringTests(unittest.TestCase):
    def test_domain_risk_rewards_similarity_newness_keywords_mx_and_https(self):
        now = datetime(2026, 8, 30, tzinfo=timezone.utc)
        observation = DomainObservation(
            domain="example-login.com",
            seed_domain="example.com",
            dns=DNSRecordSet(addresses=("203.0.113.10",), mx_records=("mail.example-login.com",)),
            registered_at=now - timedelta(days=3),
            tls=TLSInfo(https_available=True),
        )

        score = domain_risk(observation, now=now)

        self.assertEqual(65, score.value)
        self.assertIn("登録から30日以内", score.reasons)

    def test_content_risk_rewards_brand_and_visual_similarity(self):
        observation = ContentObservation(
            domain="example-login.com",
            title="Example Account",
            text="Sign in to Example",
            has_login_form=True,
            html_similarity=0.82,
            favicon_similarity=0.9,
            screenshot_similarity=0.95,
        )

        score = content_risk(observation, brand_terms=("Example",))

        self.assertEqual(100, score.value)

    def test_overall_risk_weights_content_slightly_more_than_domain(self):
        domain_score = type("S", (), {"value": 50})()
        content_score = type("S", (), {"value": 90})()

        self.assertEqual(72, overall_risk(domain_score=domain_score, content_score=content_score))


if __name__ == "__main__":
    unittest.main()
