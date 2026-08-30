import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from phishfinder.models import ContentObservation, ContentResult, DNSRecordSet, DomainObservation, Score, TLSInfo
from phishfinder.pipeline import RankedDomain
from phishfinder.report import ranked_domains_to_jsonable, write_review_csv


class ReportTests(unittest.TestCase):
    def test_ranked_domains_to_jsonable_contains_core_fields(self):
        ranked = [
            RankedDomain(
                domain="example-login.com",
                score=Score(65, ("similar", "new")),
                observation=DomainObservation(
                    domain="example-login.com",
                    seed_domain="example.com",
                    dns=DNSRecordSet(
                        addresses=("203.0.113.10",),
                        mx_records=("mail.example-login.com",),
                        name_servers=("ns1.example-login.com",),
                    ),
                    registered_at=datetime(2026, 8, 1, tzinfo=timezone.utc),
                    tls=TLSInfo(
                        https_available=True,
                        not_before=datetime(2026, 8, 1, tzinfo=timezone.utc),
                        not_after=datetime(2026, 11, 1, tzinfo=timezone.utc),
                        issuer="Example CA",
                    ),
                ),
                content=ContentResult(
                    observation=ContentObservation(
                        domain="example-login.com",
                        url="https://example-login.com/",
                        status_code=200,
                        title="Example Login",
                        text="Example Login",
                        html="<title>Example Login</title>",
                        has_login_form=True,
                    ),
                    score=Score(40, ("ページ内にブランド名が存在", "ログインフォームあり")),
                ),
                screenshot_path=Path("reports/screenshots/example.com/candidates/example-login.com.png"),
            )
        ]

        payload = ranked_domains_to_jsonable(ranked)

        self.assertEqual("example-login.com", payload[0]["domain"])
        self.assertEqual(65, payload[0]["domain_risk"])
        self.assertEqual(["similar", "new"], payload[0]["reasons"])
        self.assertEqual(["203.0.113.10"], payload[0]["dns"]["addresses"])
        self.assertTrue(payload[0]["tls"]["https_available"])
        self.assertEqual(40, payload[0]["content_risk"])
        self.assertEqual(200, payload[0]["http"]["status_code"])
        self.assertEqual("Example Login", payload[0]["http"]["title"])
        self.assertEqual(
            "reports/screenshots/example.com/candidates/example-login.com.png",
            payload[0]["screenshot_path"],
        )
        json.dumps(payload)

    def test_write_review_csv_has_human_label_column(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "review.csv"
            write_review_csv(path, [])

            text = path.read_text(encoding="utf-8-sig")

        self.assertIn("human_label", text)
        self.assertIn("memo", text)


if __name__ == "__main__":
    unittest.main()
