from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from phishfinder.phishing_observer import (
    FeedConfig,
    PhishingObserverConfig,
    UrlRecord,
    detect_brand_terms,
    is_blank_screenshot,
    is_verified_online_or_unknown,
    is_http_success_status,
    is_reference_host,
    load_observer_config,
    normalize_url,
    record_matches_target_terms,
    row_is_http_success,
    safe_name,
    suggest_label,
    url_matches_target_terms,
)


class PhishingObserverTests(unittest.TestCase):
    def test_normalize_url_accepts_only_http_urls(self) -> None:
        self.assertEqual(normalize_url("https://example.com/login"), "https://example.com/login")
        self.assertEqual(normalize_url("http://example.com/"), "http://example.com/")
        self.assertIsNone(normalize_url("javascript:alert(1)"))
        self.assertIsNone(normalize_url("ftp://example.com/file"))
        self.assertIsNone(normalize_url("example.com"))

    def test_normalize_url_rejects_embedded_credentials(self) -> None:
        self.assertIsNone(normalize_url("https://user:pass@example.com/"))

    def test_detect_brand_terms_is_case_insensitive(self) -> None:
        matched = detect_brand_terms("Fake Rakuten login", ("rakuten", "line"))
        self.assertEqual(matched, ("rakuten",))

    def test_detect_brand_terms_does_not_match_inside_words(self) -> None:
        matched = detect_brand_terms("accept payments online", ("line",))
        self.assertEqual(matched, ())

    def test_url_matches_target_terms_filters_by_substring(self) -> None:
        self.assertTrue(url_matches_target_terms("https://example.com/docomo/login", ("docomo",)))
        self.assertFalse(url_matches_target_terms("https://example.com/login", ("docomo",)))
        self.assertFalse(
            url_matches_target_terms(
                "https://dashboardaccount-moviepremiumnetfix.example/login",
                ("daccount",),
            )
        )
        self.assertFalse(
            url_matches_target_terms(
                "https://gov.myminfin-idaccount.example/",
                ("daccount",),
            )
        )
        self.assertFalse(
            url_matches_target_terms(
                "https://ee-suspended-account.web.app/",
                ("d account",),
            )
        )
        self.assertFalse(
            url_matches_target_terms(
                "https://meta-checkpoint-blocked-accounts.start.page/",
                ("d account",),
            )
        )

    def test_record_matches_target_terms_uses_reported_target(self) -> None:
        record = UrlRecord(
            url="https://random-host.example/login",
            source="phishtank",
            reported_target="NTT Docomo",
        )

        self.assertTrue(record_matches_target_terms(record, ("docomo",)))

    def test_record_matches_target_terms_tolerates_missing_target(self) -> None:
        record = UrlRecord(
            url="https://random-host.example/login",
            source="phishtank",
            reported_target=None,  # type: ignore[arg-type]
        )

        self.assertFalse(record_matches_target_terms(record, ("docomo",)))

    def test_verified_online_filter_allows_phishtank_online_rows(self) -> None:
        self.assertTrue(
            is_verified_online_or_unknown(
                UrlRecord(
                    url="https://example.com/",
                    source="phishtank",
                    verified="yes",
                    online="yes",
                )
            )
        )

    def test_http_success_status_accepts_only_200_to_399(self) -> None:
        self.assertTrue(is_http_success_status(200))
        self.assertTrue(is_http_success_status("302"))
        self.assertFalse(is_http_success_status(404))
        self.assertFalse(is_http_success_status(503))
        self.assertFalse(is_http_success_status(None))

    def test_row_success_rejects_chrome_error_pages(self) -> None:
        self.assertFalse(
            row_is_http_success(
                {
                    "status_code": 200,
                    "final_url": "chrome-error://chromewebdata/",
                    "screenshot_path": "screenshots/blank.png",
                }
            )
        )

    def test_reference_host_is_excluded(self) -> None:
        config = PhishingObserverConfig(
            feeds=(),
            reference_sites={"mufg": "https://www.bk.mufg.jp/"},
        )

        self.assertTrue(is_reference_host("www.bk.mufg.jp", config))
        self.assertFalse(is_reference_host("fake-bk.mufg.example", config))

    def test_blank_screenshot_detection(self) -> None:
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "blank.png"
            from PIL import Image

            Image.new("RGB", (64, 32), "white").save(path)

            self.assertTrue(is_blank_screenshot(path))
        self.assertFalse(
            is_verified_online_or_unknown(
                UrlRecord(
                    url="https://example.com/",
                    source="phishtank",
                    verified="yes",
                    online="no",
                )
            )
        )

    def test_suggest_label_marks_password_page_with_brand_as_phishing_suspected(self) -> None:
        self.assertEqual(
            suggest_label(form_count=1, password_count=1, matched_terms=("rakuten",)),
            "\u30d5\u30a3\u30c3\u30b7\u30f3\u30b0\u7591\u3044",
        )
        self.assertEqual(
            suggest_label(form_count=1, password_count=0, matched_terms=("rakuten",)),
            "\u78ba\u8a8d\u5bfe\u8c61",
        )
        self.assertEqual(
            suggest_label(form_count=0, password_count=0, matched_terms=("rakuten",)),
            "\u30d6\u30e9\u30f3\u30c9\u540d\u3042\u308a",
        )

    def test_safe_name_removes_path_unsafe_characters(self) -> None:
        self.assertEqual(safe_name("https://example.com/a?b=c"), "https_example.com_a_b_c")

    def test_load_observer_config_reads_json_with_comments(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.json"
            config_path.write_text(
                """
                {
                  // one URL only
                  "max_urls": 1,
                  "max_checked_urls": 7,
                  "wait_until_network_idle": false,
                  "wait_for_stable_body_ms": 0,
                  "require_verified_online": true,
                  "require_http_success": true,
                  "exclude_reference_hosts": false,
                  "manual_urls_path": "phishing_capture/manual_urls.txt",
                  "feeds": [
                    {
                      "name": "sample",
                      "enabled": false,
                      "url": "https://example.com/feed.txt",
                      "format": "text"
                    }
                  ],
                  "brand_terms": ["Rakuten"],
                  "target_terms": ["docomo"],
                  "reference_sites": {
                    "docomo": "https://www.docomo.ne.jp/"
                  }
                }
                """,
                encoding="utf-8",
            )

            config = load_observer_config(config_path)

        self.assertEqual(config.max_urls, 1)
        self.assertEqual(config.max_checked_urls, 7)
        self.assertFalse(config.wait_until_network_idle)
        self.assertEqual(config.wait_for_stable_body_ms, 0)
        self.assertTrue(config.require_verified_online)
        self.assertTrue(config.require_http_success)
        self.assertFalse(config.exclude_reference_hosts)
        self.assertEqual(config.manual_urls_path, Path("phishing_capture/manual_urls.txt"))
        self.assertEqual(
            config.feeds,
            (
                FeedConfig(
                    name="sample",
                    enabled=False,
                    url="https://example.com/feed.txt",
                    format="text",
                ),
            ),
        )
        self.assertEqual(config.brand_terms, ("rakuten",))
        self.assertEqual(config.target_terms, ("docomo",))
        self.assertEqual(config.reference_sites, {"docomo": "https://www.docomo.ne.jp/"})


if __name__ == "__main__":
    unittest.main()
