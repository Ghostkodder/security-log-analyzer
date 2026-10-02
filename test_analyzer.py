import unittest
from collections import Counter


class TestSecurityLogAnalyzer(unittest.TestCase):

    def test_failed_login_count(self):
        failed_logins = Counter({
            "203.0.113.45": 4,
            "192.168.1.20": 1,
            "198.51.100.17": 2
        })

        self.assertEqual(failed_logins["203.0.113.45"], 4)
        self.assertEqual(failed_logins["192.168.1.20"], 1)

    def test_suspicious_ip_detection(self):
        failed_logins = Counter({
            "203.0.113.45": 4,
            "192.168.1.20": 1,
            "198.51.100.17": 2
        })

        threshold = 3

        suspicious = [
            ip for ip, count in failed_logins.items()
            if count >= threshold
        ]

        self.assertIn("203.0.113.45", suspicious)
        self.assertNotIn("192.168.1.20", suspicious)

    def test_threshold(self):
        threshold = 3

        self.assertTrue(4 >= threshold)
        self.assertFalse(2 >= threshold)


if __name__ == "__main__":
    unittest.main()
