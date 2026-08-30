"""
Unit tests for TakeoverScope.

Most tests mock dns.resolver and requests so they run anywhere with no
network access. One integration test performs a real DNS lookup against
a known, stable, publicly-documented CNAME (pages.github.com ->
github.github.io) to validate the resolver logic end-to-end; it's
skipped automatically if DNS isn't reachable.

Run with:
    python3 -m unittest discover -s tests
"""

import os
import socket
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import dns.resolver  # noqa: E402
import takeoverscope as ts  # noqa: E402


def dns_available() -> bool:
    try:
        socket.getaddrinfo("pages.github.com", None)
        return True
    except OSError:
        return False


DNS_UP = dns_available()


class TestFingerprintMatching(unittest.TestCase):

    def test_matches_known_service(self):
        fp = ts.match_fingerprint("someuser.github.io", ts.DEFAULT_FINGERPRINTS)
        self.assertIsNotNone(fp)
        self.assertEqual(fp["service"], "GitHub Pages")

    def test_no_match_for_unknown_target(self):
        fp = ts.match_fingerprint("random-internal-host.corp", ts.DEFAULT_FINGERPRINTS)
        self.assertIsNone(fp)

    def test_case_insensitive_match(self):
        fp = ts.match_fingerprint("SomeApp.HEROKUAPP.COM", ts.DEFAULT_FINGERPRINTS)
        self.assertIsNotNone(fp)
        self.assertEqual(fp["service"], "Heroku")


class TestClassificationWithMocks(unittest.TestCase):

    def test_nxdomain_dangling_known_service_is_vulnerable(self):
        def fake_resolve(hostname, rtype):
            if hostname == "dangling.example.com" and rtype == "CNAME":
                m = MagicMock()
                m.target = "someuser.github.io."
                return [m]
            if hostname == "someuser.github.io":
                raise dns.resolver.NXDOMAIN()
            raise dns.resolver.NoAnswer()

        resolver = MagicMock()
        resolver.resolve.side_effect = fake_resolve

        result = ts.scan_target("dangling.example.com", resolver, ts.DEFAULT_FINGERPRINTS,
                                 timeout=5, skip_http=True)
        self.assertEqual(result.verdict, "VULNERABLE")
        self.assertEqual(result.matched_service, "GitHub Pages")

    def test_http_fingerprint_match_is_vulnerable(self):
        def fake_resolve(hostname, rtype):
            if hostname == "blog.example.com" and rtype == "CNAME":
                m = MagicMock()
                m.target = "ghost-blog.surge.sh."
                return [m]
            if hostname == "ghost-blog.surge.sh" and rtype == "CNAME":
                raise dns.resolver.NoAnswer()
            if hostname == "ghost-blog.surge.sh" and rtype == "A":
                m2 = MagicMock()
                m2.address = "1.2.3.4"
                return [m2]
            raise dns.resolver.NoAnswer()

        resolver = MagicMock()
        resolver.resolve.side_effect = fake_resolve

        fake_response = MagicMock()
        fake_response.text = "<html><body>project not found</body></html>"

        with patch("requests.get", return_value=fake_response):
            result = ts.scan_target("blog.example.com", resolver, ts.DEFAULT_FINGERPRINTS,
                                     timeout=5, skip_http=False)
        self.assertEqual(result.verdict, "VULNERABLE")
        self.assertEqual(result.http_fingerprint_matched, "project not found")

    def test_unknown_service_dangling_is_suspicious(self):
        def fake_resolve(hostname, rtype):
            if hostname == "old.example.com" and rtype == "CNAME":
                m = MagicMock()
                m.target = "legacy.some-random-startup.io."
                return [m]
            if hostname == "legacy.some-random-startup.io":
                raise dns.resolver.NXDOMAIN()
            raise dns.resolver.NoAnswer()

        resolver = MagicMock()
        resolver.resolve.side_effect = fake_resolve

        result = ts.scan_target("old.example.com", resolver, ts.DEFAULT_FINGERPRINTS,
                                 timeout=5, skip_http=True)
        self.assertEqual(result.verdict, "SUSPICIOUS")

    def test_claimed_healthy_service_is_not_vulnerable(self):
        def fake_resolve(hostname, rtype):
            if hostname == "shop.example.com" and rtype == "CNAME":
                m = MagicMock()
                m.target = "realstore.myshopify.com."
                return [m]
            if hostname == "realstore.myshopify.com" and rtype == "CNAME":
                raise dns.resolver.NoAnswer()
            if hostname == "realstore.myshopify.com" and rtype == "A":
                m2 = MagicMock()
                m2.address = "5.6.7.8"
                return [m2]
            raise dns.resolver.NoAnswer()

        resolver = MagicMock()
        resolver.resolve.side_effect = fake_resolve

        fake_response = MagicMock()
        fake_response.text = "<html><body>Welcome to Real Store!</body></html>"

        with patch("requests.get", return_value=fake_response):
            result = ts.scan_target("shop.example.com", resolver, ts.DEFAULT_FINGERPRINTS,
                                     timeout=5, skip_http=False)
        self.assertEqual(result.verdict, "NOT_VULNERABLE")

    def test_no_cname_is_not_applicable(self):
        def fake_resolve(hostname, rtype):
            if rtype == "CNAME":
                raise dns.resolver.NoAnswer()
            m = MagicMock()
            m.address = "9.9.9.9"
            return [m]

        resolver = MagicMock()
        resolver.resolve.side_effect = fake_resolve

        result = ts.scan_target("direct.example.com", resolver, ts.DEFAULT_FINGERPRINTS,
                                 timeout=5, skip_http=True)
        self.assertEqual(result.verdict, "NOT_APPLICABLE")
        self.assertEqual(result.cname_chain, [])


class TestFingerprintLoading(unittest.TestCase):

    def test_default_fingerprints_used_when_no_path(self):
        fps = ts.load_fingerprints(None)
        self.assertEqual(fps, ts.DEFAULT_FINGERPRINTS)

    def test_custom_fingerprints_loaded_from_file(self):
        import json
        import tempfile
        custom = [{"service": "Test", "cname": ["test.example"], "http": ["nope"], "nxdomain_confirms": True}]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(custom, f)
            path = f.name
        try:
            loaded = ts.load_fingerprints(path)
            self.assertEqual(loaded, custom)
        finally:
            os.unlink(path)


@unittest.skipUnless(DNS_UP, "DNS resolution not available in this environment")
class TestLiveDNSResolution(unittest.TestCase):
    """Validates the CNAME-chain resolver against a real, stable, publicly
    documented CNAME record rather than only mocks."""

    def test_resolves_real_known_cname(self):
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 8
        resolver.timeout = 8
        chain = ts.resolve_cname_chain("pages.github.com", resolver)
        self.assertTrue(len(chain) >= 1)
        self.assertIn("github.io", chain[-1])


if __name__ == "__main__":
    unittest.main()
