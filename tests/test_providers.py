"""Unit tests for threat intelligence providers."""

import unittest
from cti_toolbox.providers import misp, xforce


class TestProviders(unittest.TestCase):
    def test_stix_bundle_creation(self):
        indicators = {
            "md5": ["5d41402abc4b2a76b9719d911017c592"],
            "ip-src": ["192.168.1.100"],
            "domain": ["evil.example.com"],
        }
        bundle = misp.create_stix_bundle(indicators)
        self.assertEqual(bundle["type"], "bundle")
        self.assertEqual(len(bundle["objects"]), 3)
        patterns = [obj["pattern"] for obj in bundle["objects"]]
        self.assertTrue(any("hashes.md5" in p for p in patterns))
        self.assertTrue(any("ipv4-addr:value" in p for p in patterns))
        self.assertTrue(any("domain-name:value" in p for p in patterns))

    def test_extract_ip_helper(self):
        text = "Threat report from 198.51.100.44 on server"
        ip = xforce.extractIP(text)
        self.assertEqual(ip, "198.51.100.44")


if __name__ == "__main__":
    unittest.main()
