import unittest

from configure import render_hysteria_stats


class HysteriaStatsConfigTest(unittest.TestCase):
    def test_preserves_auth_and_acme_and_is_idempotent(self):
        original = (
            "listen: :443\n"
            "acme:\n  domains:\n    - example.org\n"
            "auth:\n  type: http\n  http:\n    url: http://127.0.0.1:18081/v1/hysteria/auth\n"
            "masquerade:\n  type: string\n"
        )
        result = render_hysteria_stats(original, "a" * 64)
        self.assertEqual(result.count("trafficStats:"), 1)
        self.assertIn("listen: 127.0.0.1:19999", result)
        self.assertIn("url: http://127.0.0.1:18081/v1/hysteria/auth", result)
        self.assertEqual(render_hysteria_stats(result, "a" * 64), result)

    def test_replaces_existing_stats_without_duplicating_following_section(self):
        original = "listen: :443\ntrafficStats:\n  listen: :9999\n  secret: old\nmasquerade:\n  type: string\n"
        result = render_hysteria_stats(original, "b" * 64)
        self.assertEqual(result.count("trafficStats:"), 1)
        self.assertEqual(result.count("masquerade:"), 1)
        self.assertNotIn("secret: old", result)


if __name__ == "__main__":
    unittest.main()
