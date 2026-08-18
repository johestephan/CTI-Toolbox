"""Unit tests for config module."""

import os
import unittest
from cti_toolbox import config


class TestConfig(unittest.TestCase):
    def test_default_version(self):
        self.assertEqual(config.VERSION, "1.1.0")

    def test_env_override(self):
        os.environ["OTX_AUTHKEY"] = "mock_otx_token_123"
        val = config.get_config("otx_authkey")
        self.assertEqual(val, "mock_otx_token_123")
        del os.environ["OTX_AUTHKEY"]

    def test_validate_key(self):
        self.assertFalse(config.validate_key("test_key", ""))
        self.assertFalse(config.validate_key("test_key", "CHANGEME"))
        self.assertTrue(config.validate_key("test_key", "valid_api_key_string"))


if __name__ == "__main__":
    unittest.main()
