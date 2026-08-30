import unittest
from urllib.error import URLError

from phishfinder.favicon_probe import FaviconProbe, favicon_similarity


class _Response:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self, limit: int) -> bytes:
        return self.payload[:limit]


class FaviconProbeTests(unittest.TestCase):
    def test_favicon_similarity_returns_one_for_same_bytes(self):
        self.assertEqual(1.0, favicon_similarity(b"abc", b"abc"))

    def test_lookup_fetches_favicon_ico(self):
        requested = []

        def fetcher(request, timeout):
            requested.append(request.full_url)
            return _Response(b"icon")

        probe = FaviconProbe(fetcher=fetcher)

        self.assertEqual(b"icon", probe.lookup("example.com", ("8.8.8.8",)))
        self.assertEqual(["https://example.com/favicon.ico"], requested)

    def test_lookup_falls_back_to_http(self):
        def fetcher(request, timeout):
            if request.full_url.startswith("https://"):
                raise URLError("no https")
            return _Response(b"icon")

        probe = FaviconProbe(fetcher=fetcher)

        self.assertEqual(b"icon", probe.lookup("example.com", ("8.8.8.8",)))

    def test_lookup_skips_private_ip_targets(self):
        probe = FaviconProbe(fetcher=lambda request, timeout: _Response(b"icon"))

        self.assertIsNone(probe.lookup("example.com", ("127.0.0.1",)))


if __name__ == "__main__":
    unittest.main()
