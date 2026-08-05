import unittest
from unittest.mock import patch

from threathub.aggregator import _score
from threathub.cli import _detect_kind
from threathub.sources import guess_service


class TestDetectKind(unittest.TestCase):
    def test_detection(self):
        self.assertEqual(_detect_kind("8.8.8.8"), "ip")
        self.assertEqual(_detect_kind("example.com"), "domain")
        self.assertEqual(_detect_kind("user@example.com"), "email")
        self.assertEqual(_detect_kind("CVE-2021-44228"), "cve")


class TestScoring(unittest.TestCase):
    def test_benign(self):
        r = _score({"abuseipdb": {}, "virustotal": {}, "greynoise": {}})
        self.assertEqual(r["level"], "benign")
        self.assertEqual(r["score"], 0)

    def test_high(self):
        r = _score({"abuseipdb": {"abuseConfidenceScore": 80},
                    "virustotal": {"malicious": 3},
                    "greynoise": {"classification": "malicious"}})
        self.assertEqual(r["level"], "high")
        self.assertGreaterEqual(r["score"], 50)

    def test_tor_note(self):
        r = _score({"tor-exit-list": {"is_tor": True}, "abuseipdb": {}})
        self.assertEqual(r["level"], "low")
        self.assertEqual(r["score"], 15)


class TestServiceGuess(unittest.TestCase):
    def test_guess_service(self):
        self.assertIn("github", guess_service("dev@github.com"))
        self.assertIn("google", guess_service("x@gmail.com"))
        self.assertEqual(guess_service("x@custom-domain.io"), [])


if __name__ == "__main__":
    unittest.main()
