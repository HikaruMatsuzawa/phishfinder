import unittest

from phishfinder.models import DNSRecordSet
from phishfinder.pipeline import discover_existing_domains, rank_domains


class FakeDNSProbe:
    def __init__(self, existing):
        self.existing = existing

    def lookup(self, domain):
        if domain in self.existing:
            return DNSRecordSet(addresses=("203.0.113.20",))
        return DNSRecordSet()


class FakeRDAPProbe:
    def lookup_registered_at(self, domain):
        if domain == "example-login.com":
            from datetime import datetime, timezone

            return datetime(2026, 8, 1, tzinfo=timezone.utc)
        return None


class FakeTLSProbe:
    def lookup(self, domain):
        from phishfinder.models import TLSInfo

        return TLSInfo(https_available=domain == "example-login.com")


class PipelineTests(unittest.TestCase):
    def test_discovers_only_domains_with_addresses(self):
        observations = discover_existing_domains(
            "example.com",
            dns_probe=FakeDNSProbe({"examle.com", "example-login.com"}),
        )

        self.assertEqual(["examle.com", "example-login.com"], [item.domain for item in observations])

    def test_rank_domains_sorts_by_risk_descending(self):
        observations = discover_existing_domains(
            "example.com",
            dns_probe=FakeDNSProbe({"example-login.com", "examle.com"}),
        )

        ranked = rank_domains(observations)

        self.assertEqual("example-login.com", ranked[0].domain)

    def test_can_enrich_existing_domains_with_rdap_registration_date(self):
        observations = discover_existing_domains(
            "example.com",
            dns_probe=FakeDNSProbe({"example-login.com"}),
            rdap_probe=FakeRDAPProbe(),
        )

        self.assertEqual(2026, observations[0].registered_at.year)

    def test_can_enrich_existing_domains_with_tls_info(self):
        observations = discover_existing_domains(
            "example.com",
            dns_probe=FakeDNSProbe({"example-login.com"}),
            tls_probe=FakeTLSProbe(),
        )

        self.assertTrue(observations[0].tls.https_available)

    def test_can_scan_a_supplied_candidate_list(self):
        observations = discover_existing_domains(
            "example.com",
            dns_probe=FakeDNSProbe({"custom-example.com"}),
            candidates=["custom-example.com"],
        )

        self.assertEqual(["custom-example.com"], [item.domain for item in observations])

    def test_can_wrap_candidates_with_progress_factory(self):
        calls = []

        def progress_factory(items):
            calls.append(list(items))
            return calls[0]

        observations = discover_existing_domains(
            "example.com",
            dns_probe=FakeDNSProbe({"custom-example.com"}),
            candidates=["custom-example.com"],
            progress_factory=progress_factory,
        )

        self.assertEqual([["custom-example.com"]], calls)
        self.assertEqual(["custom-example.com"], [item.domain for item in observations])


if __name__ == "__main__":
    unittest.main()
