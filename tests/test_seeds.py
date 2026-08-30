import unittest

from phishfinder.seeds import parse_seed_lines, parse_tranco_csv


class SeedTests(unittest.TestCase):
    def test_parse_seed_lines_ignores_blank_lines_and_comments(self):
        lines = [
            "# メモ",
            "",
            " Example.COM ",
            "invalid",
            "openai.com # inline comment",
        ]

        self.assertEqual(("example.com", "openai.com"), parse_seed_lines(lines))

    def test_parse_tranco_csv_accepts_ranked_csv(self):
        text = "1,google.com\n2,youtube.com\n"

        self.assertEqual(("google.com", "youtube.com"), parse_tranco_csv(text, limit=2))

    def test_parse_tranco_csv_accepts_one_domain_per_line(self):
        text = "google.com\nyoutube.com\n"

        self.assertEqual(("google.com",), parse_tranco_csv(text, limit=1))


if __name__ == "__main__":
    unittest.main()
