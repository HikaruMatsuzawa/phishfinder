import subprocess
import unittest

from phishfinder.dns_probe import DNSProbe, parse_nslookup_records


class DNSProbeTests(unittest.TestCase):
    def test_parse_nslookup_mx_records(self):
        output = """
example.com     MX preference = 10, mail exchanger = mail.example.com
example.com     MX preference = 20, mail exchanger = backup.example.com
"""

        self.assertEqual(
            ("backup.example.com", "mail.example.com"),
            parse_nslookup_records(output, "MX"),
        )

    def test_parse_nslookup_ns_records(self):
        output = """
example.com     nameserver = ns1.example.com
example.com     nameserver = ns2.example.com
"""

        self.assertEqual(
            ("ns1.example.com", "ns2.example.com"),
            parse_nslookup_records(output, "NS"),
        )

    def test_lookup_includes_mx_and_name_servers(self):
        def resolver(domain):
            self.assertEqual("example.com", domain)
            return ["203.0.113.10"]

        def runner(args, capture_output, text, timeout, check):
            query_type = args[1]
            if query_type == "-type=MX":
                stdout = "example.com MX preference = 10, mail exchanger = mail.example.com"
            elif query_type == "-type=NS":
                stdout = "example.com nameserver = ns1.example.com"
            else:
                stdout = ""
            return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")

        probe = DNSProbe(address_resolver=resolver, command_runner=runner, include_details=True)

        records = probe.lookup("example.com")

        self.assertEqual(("203.0.113.10",), records.addresses)
        self.assertEqual(("mail.example.com",), records.mx_records)
        self.assertEqual(("ns1.example.com",), records.name_servers)

    def test_lookup_skips_mx_and_ns_by_default(self):
        calls = []

        def resolver(domain):
            return ["203.0.113.10"]

        def runner(args, capture_output, text, timeout, check):
            calls.append(args)
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

        probe = DNSProbe(address_resolver=resolver, command_runner=runner)

        records = probe.lookup("example.com")

        self.assertEqual(("203.0.113.10",), records.addresses)
        self.assertEqual((), records.mx_records)
        self.assertEqual((), records.name_servers)
        self.assertEqual([], calls)

    def test_lookup_survives_nslookup_failure(self):
        def resolver(domain):
            return ["203.0.113.10"]

        def runner(args, capture_output, text, timeout, check):
            raise subprocess.TimeoutExpired(args, timeout)

        probe = DNSProbe(address_resolver=resolver, command_runner=runner, include_details=True)

        records = probe.lookup("example.com")

        self.assertEqual(("203.0.113.10",), records.addresses)
        self.assertEqual((), records.mx_records)
        self.assertEqual((), records.name_servers)


if __name__ == "__main__":
    unittest.main()
