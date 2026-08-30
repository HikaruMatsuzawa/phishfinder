import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import run
from phishfinder.config import AppConfig, ReviewConfig, ScreenshotConfig
from phishfinder.models import ContentObservation, DNSRecordSet, DomainObservation
from phishfinder.pipeline import RankedDomain
from phishfinder.scoring import domain_risk


class RunConfigTests(unittest.TestCase):
    def test_resolve_path_keeps_absolute_path(self):
        path = Path.cwd().resolve()

        self.assertEqual(path, run.resolve_path(path))

    def test_resolve_path_makes_relative_path_repo_relative(self):
        self.assertEqual(run.ROOT / "data/seeds.txt", run.resolve_path(Path("data/seeds.txt")))

    def test_display_path_prefers_repo_relative_path(self):
        self.assertEqual("reports/domain_report.json", run.display_path(Path("reports/domain_report.json")))

    def test_resolve_screenshot_config_preserves_include_seed(self):
        config = ScreenshotConfig(
            enabled=True,
            limit=3,
            output_dir=Path("reports/screenshots"),
            timeout_seconds=4,
            javascript_enabled=True,
            include_seed=False,
        )

        resolved = run.resolve_screenshot_config(config)

        self.assertEqual(run.ROOT / "reports/screenshots", resolved.output_dir)
        self.assertFalse(resolved.include_seed)

    def test_scan_from_config_writes_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            seeds = tmp_path / "seeds.txt"
            report = tmp_path / "report.json"
            seeds.write_text("example.com\n", encoding="utf-8")
            config = AppConfig(
                seeds_path=seeds,
                seed_limit=1,
                variant_limit=1,
                progress=False,
                output_path=report,
                review=ReviewConfig(output_path=tmp_path / "review.csv"),
            )

            observation = DomainObservation(
                domain="examle.com",
                seed_domain="example.com",
                dns=DNSRecordSet(addresses=("203.0.113.10",)),
            )
            with patch.object(run, "discover_existing_domains", return_value=[observation]):
                with patch.object(run, "enrich_with_http_metadata", side_effect=lambda config, ranked: ranked):
                    exit_code = run.scan_from_config(config)

            self.assertEqual(0, exit_code)
            self.assertTrue(report.exists())

    def test_scan_from_config_runs_screenshots_when_enabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            seeds = tmp_path / "seeds.txt"
            report = tmp_path / "report.json"
            screenshots = tmp_path / "screenshots"
            seeds.write_text("example.com\n", encoding="utf-8")
            config = AppConfig(
                seeds_path=seeds,
                seed_limit=1,
                variant_limit=1,
                progress=False,
                output_path=report,
                screenshots=ScreenshotConfig(enabled=True, output_dir=screenshots),
                review=ReviewConfig(output_path=tmp_path / "review.csv"),
            )
            observation = DomainObservation(
                domain="examle.com",
                seed_domain="example.com",
                dns=DNSRecordSet(addresses=("8.8.8.8",)),
            )

            with patch.object(run, "discover_existing_domains", return_value=[observation]):
                with patch.object(run, "enrich_with_http_metadata", side_effect=lambda config, ranked: ranked):
                    with patch.object(
                        run.ScreenshotProbe,
                        "capture",
                        return_value={"examle.com": screenshots / "x.png"},
                    ) as capture:
                        exit_code = run.scan_from_config(config)

            self.assertEqual(0, exit_code)
            capture.assert_called_once()

    def test_enrich_with_http_metadata_adds_content_score(self):
        config = AppConfig(progress=False)
        domain_observation = DomainObservation(
            "example-login.com",
            "example.com",
            dns=DNSRecordSet(addresses=("8.8.8.8",)),
        )
        ranked = [
            RankedDomain(
                "example-login.com",
                domain_risk(domain_observation),
                domain_observation,
            )
        ]

        with patch.object(run.HTTPProbe, "lookup") as lookup:
            lookup.return_value = ContentObservation(
                domain="example-login.com",
                url="https://example-login.com/",
                status_code=200,
                title="Example",
                text="Example",
                has_login_form=True,
            )
            enriched = run.enrich_with_http_metadata(config, ranked)

        self.assertIsNotNone(enriched[0].content)
        self.assertEqual(40, enriched[0].content.score.value)


if __name__ == "__main__":
    unittest.main()
