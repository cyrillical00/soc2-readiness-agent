"""The per-visitor limit must not be keyed on a value the visitor controls."""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import rate_limiter  # noqa: E402


class ClientIpTests(unittest.TestCase):
    def test_right_most_hop_is_used_not_the_client_supplied_one(self):
        ip = rate_limiter.get_client_ip({"X-Forwarded-For": "1.1.1.1, 203.0.113.7"})
        self.assertEqual(ip, "203.0.113.7")

    def test_rotating_the_spoofable_part_does_not_change_the_key(self):
        keys = {
            rate_limiter.get_client_ip({"x-forwarded-for": f"10.0.0.{n}, 198.51.100.{n}, 203.0.113.7"})
            for n in range(20)
        }
        self.assertEqual(keys, {"203.0.113.7"})

    def test_header_name_is_matched_case_insensitively(self):
        for name in ("x-forwarded-for", "X-Forwarded-For", "X-FORWARDED-FOR"):
            self.assertEqual(rate_limiter.get_client_ip({name: "203.0.113.7"}), "203.0.113.7", name)

    def test_other_client_settable_headers_are_ignored(self):
        self.assertEqual(rate_limiter.get_client_ip({"x-real-ip": "1.1.1.1"}), "unknown")
        self.assertEqual(rate_limiter.get_client_ip({"cf-connecting-ip": "1.1.1.1"}), "unknown")
        self.assertEqual(
            rate_limiter.get_client_ip({"x-real-ip": "1.1.1.1", "x-forwarded-for": "203.0.113.7"}),
            "203.0.113.7",
        )

    def test_missing_or_malformed_values_share_one_bucket(self):
        for headers in ({}, {"x-forwarded-for": ""}, {"x-forwarded-for": "not-an-ip"}, {"x-forwarded-for": "1.1.1.1, <script>"}):
            self.assertEqual(rate_limiter.get_client_ip(headers), "unknown", headers)

    def test_ipv6_is_accepted(self):
        self.assertEqual(rate_limiter.get_client_ip({"x-forwarded-for": "1.1.1.1, 2001:db8::1"}), "2001:db8::1")

    def test_more_trusted_proxies_shift_the_hop(self):
        with mock.patch.object(rate_limiter, "TRUSTED_PROXY_HOPS", 2):
            self.assertEqual(
                rate_limiter.get_client_ip({"x-forwarded-for": "1.1.1.1, 203.0.113.7, 10.0.0.1"}),
                "203.0.113.7",
            )
            self.assertEqual(rate_limiter.get_client_ip({"x-forwarded-for": "10.0.0.1"}), "unknown")


class CounterTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        patcher = mock.patch.object(rate_limiter, "LIMIT_FILE", os.path.join(self.dir.name, "limits.json"))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_limit_is_enforced_per_key(self):
        for used in range(rate_limiter.DAILY_LIMIT):
            allowed, remaining = rate_limiter.check_limit("203.0.113.7")
            self.assertTrue(allowed)
            self.assertEqual(remaining, rate_limiter.DAILY_LIMIT - used)
            rate_limiter.record_run("203.0.113.7")
        self.assertEqual(rate_limiter.check_limit("203.0.113.7"), (False, 0))
        self.assertEqual(rate_limiter.check_limit("203.0.113.8"), (True, rate_limiter.DAILY_LIMIT))

    def test_spoofed_left_hand_values_draw_on_the_same_allowance(self):
        for n in range(rate_limiter.DAILY_LIMIT):
            ip = rate_limiter.get_client_ip({"X-Forwarded-For": f"10.9.8.{n}, 203.0.113.7"})
            self.assertTrue(rate_limiter.check_limit(ip)[0])
            rate_limiter.record_run(ip)
        ip = rate_limiter.get_client_ip({"X-Forwarded-For": "10.9.8.250, 203.0.113.7"})
        self.assertFalse(rate_limiter.check_limit(ip)[0])

    def test_old_entries_are_dropped_on_write(self):
        rate_limiter._save({"198.51.100.1": {"date": "2000-01-01", "count": 5}, "junk": "x"})
        rate_limiter.record_run("203.0.113.7")
        self.assertEqual(list(rate_limiter._load()), ["203.0.113.7"])


if __name__ == "__main__":
    unittest.main()
