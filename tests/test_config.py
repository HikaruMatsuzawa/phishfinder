import tempfile
import unittest
from pathlib import Path

from phishfinder.config import AppConfig, load_config, strip_json_comments


class ConfigTests(unittest.TestCase):
    def test_load_config_returns_defaults_when_file_is_missing(self):
        config = load_config(Path("missing-config.json"))

        self.assertEqual(AppConfig(), config)

    def test_load_config_reads_all_scan_settings(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(
                """
{
  "seeds_path": "data/custom.txt",
  "seed_limit": 10,
  "variant_limit": 500,
  "dns_details": true,
  "rdap": true,
  "tls": true,
  "progress": false,
  "output_format": "csv",
  "output_path": "reports/custom.csv",
  "http": {
    "enabled": true,
    "limit": 7,
    "timeout_seconds": 4,
    "max_html_bytes": 12345,
    "user_agent": "test-agent",
    "favicon_enabled": false
  },
  "screenshots": {
    "enabled": true,
    "limit": 5,
    "output_dir": "reports/screens",
    "timeout_seconds": 3,
    "javascript_enabled": false,
    "include_seed": true
  },
  "review": {
    "enabled": true,
    "output_path": "reports/review.csv"
  }
}
""",
                encoding="utf-8",
            )

            config = load_config(path)

        self.assertEqual(Path("data/custom.txt"), config.seeds_path)
        self.assertEqual(10, config.seed_limit)
        self.assertEqual(500, config.variant_limit)
        self.assertTrue(config.dns_details)
        self.assertTrue(config.rdap)
        self.assertTrue(config.tls)
        self.assertFalse(config.progress)
        self.assertEqual("csv", config.output_format)
        self.assertEqual(Path("reports/custom.csv"), config.output_path)
        self.assertTrue(config.http.enabled)
        self.assertEqual(7, config.http.limit)
        self.assertEqual("test-agent", config.http.user_agent)
        self.assertFalse(config.http.favicon_enabled)
        self.assertTrue(config.screenshots.enabled)
        self.assertEqual(5, config.screenshots.limit)
        self.assertTrue(config.screenshots.include_seed)
        self.assertTrue(config.review.enabled)
        self.assertEqual(Path("reports/review.csv"), config.review.output_path)

    def test_strip_json_comments_preserves_urls_inside_strings(self):
        text = '{"url": "https://example.com/path", // コメント\n"value": 1}'

        self.assertEqual(
            '{"url": "https://example.com/path", \n"value": 1}',
            strip_json_comments(text),
        )

    def test_null_limits_mean_all_items(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text('{"seed_limit": null, "variant_limit": null}', encoding="utf-8")

            config = load_config(path)

        self.assertIsNone(config.seed_limit)
        self.assertIsNone(config.variant_limit)


if __name__ == "__main__":
    unittest.main()
