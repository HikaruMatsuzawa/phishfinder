import json
import unittest
from datetime import datetime, timezone
from urllib.error import URLError

from phishfinder.rdap_probe import RDAPProbe, parse_registered_at


class RDAPProbeTests(unittest.TestCase):
    def test_parse_registered_at_prefers_registration_event(self):
        payload = {
            "events": [
                {"eventAction": "last changed", "eventDate": "2026-08-20T00:00:00Z"},
                {"eventAction": "registration", "eventDate": "2026-08-01T12:30:00Z"},
            ]
        }

        self.assertEqual(
            datetime(2026, 8, 1, 12, 30, tzinfo=timezone.utc),
            parse_registered_at(payload),
        )

    def test_parse_registered_at_returns_none_when_missing(self):
        self.assertIsNone(parse_registered_at({"events": []}))

    def test_lookup_returns_registration_date_from_fetcher_json(self):
        def fetcher(url, timeout):
            self.assertEqual("https://rdap.org/domain/example-login.com", url)
            self.assertEqual(5.0, timeout)
            return json.dumps(
                {
                    "events": [
                        {
                            "eventAction": "registration",
                            "eventDate": "2026-08-01T12:30:00Z",
                        }
                    ]
                }
            ).encode()

        probe = RDAPProbe(fetcher=fetcher, timeout=5.0)

        self.assertEqual(
            datetime(2026, 8, 1, 12, 30, tzinfo=timezone.utc),
            probe.lookup_registered_at("example-login.com"),
        )

    def test_lookup_returns_none_on_network_error(self):
        def fetcher(url, timeout):
            raise URLError("offline")

        probe = RDAPProbe(fetcher=fetcher)

        self.assertIsNone(probe.lookup_registered_at("example-login.com"))


if __name__ == "__main__":
    unittest.main()
