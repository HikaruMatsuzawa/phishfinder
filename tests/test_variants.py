import unittest

from phishfinder.variants import generate_variants, split_domain


class VariantGenerationTests(unittest.TestCase):
    def test_generates_common_typosquatting_patterns(self):
        variants = set(generate_variants("example.com"))

        self.assertIn("examle.com", variants)
        self.assertIn("exampple.com", variants)
        self.assertIn("exmaple.com", variants)
        self.assertIn("examp1e.com", variants)
        self.assertIn("example-login.com", variants)
        self.assertIn("secure-example.com", variants)
        self.assertIn("example.net", variants)

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
