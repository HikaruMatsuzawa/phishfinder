import unittest

from phishfinder.config import HTTPConfig
from phishfinder.http_probe import (
    HTTPProbe,
    brand_terms_from_seed,
    extract_title,
    has_login_form,
    html_to_text,
)


class HTTPProbeTests(unittest.TestCase):
    def test_extract_title(self):
        html = "<html><head><title>  Example Login  </title></head></html>"

        self.assertEqual("Example Login", extract_title(html))

    def test_html_to_text_removes_scripts_and_tags(self):
        html = "<script>alert(1)</script><h1>Example</h1><p>Login</p>"

        self.assertEqual("Example Login", html_to_text(html))

    def test_has_login_form_detects_password_input(self):
        html = '<form><input type="password" name="password"></form>'

        self.assertTrue(has_login_form(html))

    def test_brand_terms_from_seed_includes_ntt_and_docomo(self):
        self.assertEqual(("docomo", "dpoint", "ntt"), brand_terms_from_seed("dpoint.docomo.ne.jp"))

    def test_lookup_fetches_title_status_and_login_form(self):
        def fetcher(url, config):
            self.assertEqual("https://example-login.com/", url)
            return (
                200,
                "utf-8",
                b"<title>Example</title><form><input type='password'></form>",
            )

        probe = HTTPProbe(HTTPConfig(timeout_seconds=1), fetcher=fetcher)

        observation = probe.lookup("example-login.com", ("8.8.8.8",))

        self.assertEqual("https://example-login.com/", observation.url)
        self.assertEqual(200, observation.status_code)
        self.assertEqual("Example", observation.title)
        self.assertTrue(observation.has_login_form)

    def test_lookup_skips_private_ip_targets(self):
        calls = []

        def fetcher(url, config):
            calls.append(url)
            return 200, "utf-8", b""

        probe = HTTPProbe(HTTPConfig(), fetcher=fetcher)

        observation = probe.lookup("internal.example", ("127.0.0.1",))

        self.assertIsNone(observation.url)
        self.assertEqual([], calls)


if __name__ == "__main__":
    unittest.main()
