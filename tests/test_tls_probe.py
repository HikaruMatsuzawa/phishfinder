import socket
import ssl
import unittest
from datetime import datetime, timezone

from phishfinder.tls_probe import TLSProbe, parse_certificate_datetime


class TLSProbeTests(unittest.TestCase):
    def test_parse_certificate_datetime(self):
        self.assertEqual(
            datetime(2026, 8, 1, 12, 30, 0, tzinfo=timezone.utc),
            parse_certificate_datetime("Aug  1 12:30:00 2026 GMT"),
        )

    def test_lookup_returns_certificate_dates_and_issuer(self):
        certificate = {
            "notBefore": "Aug  1 12:30:00 2026 GMT",
            "notAfter": "Nov  1 12:30:00 2026 GMT",
            "issuer": ((("organizationName", "Example CA"),),),
        }

        probe = TLSProbe(certificate_fetcher=lambda domain, timeout: certificate, timeout=3.0)

        info = probe.lookup("example.com")

        self.assertTrue(info.https_available)
        self.assertEqual(datetime(2026, 8, 1, 12, 30, tzinfo=timezone.utc), info.not_before)
        self.assertEqual(datetime(2026, 11, 1, 12, 30, tzinfo=timezone.utc), info.not_after)
        self.assertEqual("Example CA", info.issuer)

    def test_lookup_returns_unavailable_on_tls_error(self):
        def fetcher(domain, timeout):
            raise ssl.SSLError("handshake failed")

        probe = TLSProbe(certificate_fetcher=fetcher)

        self.assertFalse(probe.lookup("example.com").https_available)

    def test_lookup_returns_unavailable_on_socket_error(self):
        def fetcher(domain, timeout):
            raise socket.timeout("slow")

        probe = TLSProbe(certificate_fetcher=fetcher)

        self.assertFalse(probe.lookup("example.com").https_available)


if __name__ == "__main__":
    unittest.main()
