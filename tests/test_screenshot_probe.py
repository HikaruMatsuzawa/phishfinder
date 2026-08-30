import unittest
from pathlib import Path

from phishfinder.models import DNSRecordSet, DomainObservation, Score
from phishfinder.pipeline import RankedDomain
from phishfinder.screenshot_probe import (
    has_only_public_addresses,
    is_safe_http_url,
    safe_filename,
    seed_output_dir,
    screenshot_targets,
)


class ScreenshotProbeTests(unittest.TestCase):
    def test_has_only_public_addresses_rejects_private_addresses(self):
        self.assertFalse(has_only_public_addresses(("127.0.0.1",)))
        self.assertFalse(has_only_public_addresses(("192.168.0.1",)))

    def test_has_only_public_addresses_accepts_public_addresses(self):
        self.assertTrue(has_only_public_addresses(("8.8.8.8",)))

    def test_screenshot_targets_skips_private_ip_candidates(self):
        public = RankedDomain(
            "example.com",
            Score(20, ()),
            DomainObservation("example.com", "seed.com", DNSRecordSet(addresses=("8.8.8.8",))),
        )
        private = RankedDomain(
            "internal.example",
            Score(99, ()),
            DomainObservation("internal.example", "seed.com", DNSRecordSet(addresses=("10.0.0.1",))),
        )

        self.assertEqual([public], screenshot_targets([private, public], limit=10))

    def test_safe_filename_removes_unsafe_characters(self):
        self.assertEqual("example-login.com", safe_filename("example-login.com"))
        self.assertEqual("bad_name.com", safe_filename("bad/name.com"))

    def test_seed_output_dir_groups_by_seed_domain(self):
        self.assertEqual(
            "reports/screenshots/ntt.com",
            seed_output_dir(Path("reports/screenshots"), "ntt.com").as_posix(),
        )

    def test_is_safe_http_url_accepts_only_http_and_https(self):
        self.assertTrue(is_safe_http_url("https://example.com/"))
        self.assertTrue(is_safe_http_url("http://example.com/"))
        self.assertFalse(is_safe_http_url("file:///etc/passwd"))


if __name__ == "__main__":
    unittest.main()
