import unittest

from phishfinder.variants import generate_variants, split_domain


class VariantGenerationTests(unittest.TestCase):
    def test_generates_common_typosquatting_patterns(self):
        variants = set(generate_variants("example.com"))

        self.assertIn("examle.com", variants)
        self.assertIn("exampple.com", variants)
        self.assertIn("examplee.com", variants)
        self.assertIn("exmaple.com", variants)
        self.assertIn("examp1e.com", variants)
        self.assertIn("example-login.com", variants)
        self.assertIn("exampleid.com", variants)
        self.assertIn("secure-example.com", variants)
        self.assertIn("example.net", variants)

    def test_generates_keyboard_neighbor_typos(self):
        variants = set(generate_variants("rakuten.co.jp"))

        self.assertIn("eakuten.co.jp", variants)
        self.assertIn("rqkuten.co.jp", variants)

    def test_keeps_common_japanese_public_suffixes_together(self):
        self.assertEqual(("ntt-east", "co.jp"), split_domain("ntt-east.co.jp"))
        self.assertEqual(("docomo", "ne.jp"), split_domain("docomo.ne.jp"))

        variants = set(generate_variants("ntt-east.co.jp"))

        self.assertIn("ntteast.co.jp", variants)
        self.assertIn("ntt-east-login.co.jp", variants)
        self.assertIn("login-ntt-east.co.jp", variants)
        self.assertIn("ntt-east.jp", variants)

    def test_generates_security_and_payment_words(self):
        variants = set(generate_variants("paypay.ne.jp"))

        self.assertIn("paypay-security.ne.jp", variants)
        self.assertIn("paypaypay.ne.jp", variants)
        self.assertIn("id-paypay.ne.jp", variants)

    def test_idn_homograph_is_encoded_as_punycode(self):
        variants = set(generate_variants("paypal.com"))

        self.assertIn("xn--aypal-uye.com", variants)

    def test_excludes_original_domain(self):
        self.assertNotIn("example.com", generate_variants("example.com"))

    def test_rejects_invalid_seed_domain(self):
        with self.assertRaises(ValueError):
            split_domain("localhost")


if __name__ == "__main__":
    unittest.main()
