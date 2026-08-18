"""Unit tests for redact / defanging module."""

import unittest
from cti_toolbox.defang import redact


class TestRedact(unittest.TestCase):
    def test_redact_ip(self):
        self.assertEqual(redact.redact_ip("192.168.1.1"), "192.168.1[.]1")
        self.assertEqual(redact.redact_ip("10.0.0.1"), "10.0.0[.]1")

    def test_redact_email(self):
        self.assertEqual(redact.redact_email("analyst@example.com"), "analyst[@]example[.]com")
        self.assertEqual(redact.redact_email("test.user@sub.domain.org"), "test.user[@]sub.domain[.]org")

    def test_redact_schemes(self):
        self.assertEqual(redact.redact_schemes("http://example.com"), "hxxp://example.com")
        self.assertEqual(redact.redact_schemes("https://secure.site"), "hxxps://secure.site")
        self.assertEqual(redact.redact_schemes("ftp://files.host"), "fxp://files.host")

    def test_full_redaction(self):
        raw = "Suspicious traffic to http://185.117.73.160/drop by root@victim.com"
        redacted = redact.redactit(raw)
        self.assertIn("hxxp://", redacted)
        self.assertIn("185.117.73[.]160", redacted)
        self.assertIn("root[@]victim[.]com", redacted)

    def test_custom_searchkey(self):
        text = "Confidential project codename ProjectApollo"
        redacted = redact.redactit(text, searchkey="ProjectApollo,$#=[CLASSIFIED]")
        self.assertEqual(redacted, "Confidential project codename [CLASSIFIED]")


if __name__ == "__main__":
    unittest.main()
