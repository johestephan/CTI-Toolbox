"""Unit tests for indicator extraction."""

import unittest
from cti_toolbox.extract import indicators


class TestIndicators(unittest.TestCase):
    def test_get_ip(self):
        text = "Alerts on 192.168.1.100 and 8.8.8.8 detected"
        ips = indicators.getIP(text)
        self.assertIn("192.168.1.100", ips)
        self.assertIn("8.8.8.8", ips)

    def test_bogon_filtering(self):
        text = "Private 10.1.2.3 and public 93.184.216.34"
        public_only = indicators.getIP(text, filter_bogons=True)
        self.assertIn("93.184.216.34", public_only)
        self.assertNotIn("10.1.2.3", public_only)

    def test_get_hashes(self):
        text = "md5: 5d41402abc4b2a76b9719d911017c592 sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.assertIn("5d41402abc4b2a76b9719d911017c592", indicators.getMD5(text))
        self.assertIn("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", indicators.getSHA256(text))

    def test_get_cve(self):
        text = "Exploited vulnerability CVE-2021-44228 and cve_2020_0601"
        cves = indicators.getCVE(text)
        self.assertIn("CVE-2021-44228", cves)
        self.assertIn("CVE-2020-0601", cves)

    def test_get_all_indicators(self):
        text = "User test@bad.com downloaded http://evil.com/a from 1.1.1.1"
        result = indicators.get_all_indicators(text)
        self.assertEqual(result["ipv4"], ["1.1.1.1"])
        self.assertEqual(result["url"], ["http://evil.com/a"])
        self.assertEqual(result["email"], ["test@bad.com"])


if __name__ == "__main__":
    unittest.main()
