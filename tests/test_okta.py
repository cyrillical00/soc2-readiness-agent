"""The Okta connector: where the token may go, and what counts as MFA."""
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import requests  # noqa: E402

from connectors import okta  # noqa: E402

TOKEN = "not-a-real-token"
HOST = "https://acme.okta.com"


class _Response:
    def __init__(self, payload=None, status=200, next_url=None):
        self.status_code = status
        self._payload = payload if payload is not None else []
        self.links = {"next": {"url": next_url}} if next_url else {}
        self.ok = status < 400
        self.text = str(self._payload)

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")


class _FakeOkta:
    """Answers GETs from a list of (substring, response) pairs; first match wins."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def __call__(self, url, **kwargs):
        self.calls.append((url, kwargs))
        for needle, response in self.routes:
            if needle in url:
                return response(url) if callable(response) else response
        return _Response(status=404)


def _creds(domain="acme.okta.com"):
    values = {"OKTA_DOMAIN": domain, "OKTA_API_TOKEN": TOKEN}
    return mock.patch.object(okta, "secret", side_effect=lambda name, default="": values.get(name, default))


def _collect(routes, domain="acme.okta.com"):
    fake = _FakeOkta(routes)
    with _creds(domain), mock.patch.object(okta.requests, "get", side_effect=fake):
        return okta.collect(), fake


class HostTests(unittest.TestCase):
    def test_okta_hosts_are_accepted_and_normalised(self):
        for raw, expected in {
            "acme.okta.com": "acme.okta.com",
            " https://ACME.okta.com/ ": "acme.okta.com",
            "dev-123456.oktapreview.com": "dev-123456.oktapreview.com",
            "acme.okta-emea.com": "acme.okta-emea.com",
            "acme.okta-gov.com": "acme.okta-gov.com",
            "acme.okta.mil": "acme.okta.mil",
        }.items():
            self.assertEqual(okta.normalize_okta_domain(raw), expected, raw)

    def test_everything_else_is_refused(self):
        for raw in (
            "", None, "okta.com", "localhost", "127.0.0.1", "169.254.169.254",
            "internal:8443/x?", "login.example.com", "acme.okta.com.evil.example",
            "evil.example/acme.okta.com", "evil.example#.okta.com", "acme.okta.com@evil.example",
            "acme.okta.com:8443", "acme.okta.com/api", "a.b.okta.com", "acmeokta.com",
            "acme.okta.com\nHost: evil.example",
        ):
            with self.assertRaises(ValueError, msg=repr(raw)):
                okta.normalize_okta_domain(raw)

    def test_a_bad_configured_domain_sends_nothing(self):
        for domain in ("internal:8443/x?", "login.example.com", "169.254.169.254"):
            with _creds(domain), mock.patch.object(okta.requests, "get") as get:
                ok, message = okta.test_connection()
                findings = okta.collect()
                get.assert_not_called()
            self.assertFalse(ok)
            self.assertIn("OKTA_DOMAIN", message)
            self.assertIn("OKTA_DOMAIN", findings["_error"])
            self.assertNotIn("total_active_users", findings)

    def test_every_request_stays_on_the_org_and_follows_no_redirect(self):
        findings, fake = _collect([
            ("/users?filter=status+eq+%22ACTIVE%22&limit=200", _Response([{"id": "u1", "profile": {"login": "a@example.org"}}])),
            ("/factors", _Response([])),
            ("/roles", _Response([])),
            ("/users?", _Response([])),
            ("/policies", _Response([])),
            ("/apps", _Response([])),
        ])
        self.assertNotIn("_error", findings)
        self.assertGreater(len(fake.calls), 4)
        for url, kwargs in fake.calls:
            self.assertTrue(url.startswith(HOST + "/api/v1/"), url)
            self.assertIs(kwargs.get("allow_redirects"), False, url)

    def test_pagination_follows_same_host_links(self):
        def users(url):
            if "after=p2" in url:
                return _Response([{"id": "u2", "profile": {"login": "b@example.org"}}])
            return _Response([{"id": "u1", "profile": {"login": "a@example.org"}}], next_url=f"{HOST}/api/v1/users?after=p2&limit=200")

        findings, _ = _collect([
            ("lastLogin", _Response([])),
            ("/factors", _Response([])),
            ("/roles", _Response([])),
            ("/users?", users),
            ("/policies", _Response([])),
            ("/apps", _Response([])),
        ])
        self.assertNotIn("_error", findings)
        self.assertEqual(findings["total_active_users"], 2)

    def test_a_next_link_to_another_host_is_refused(self):
        for link in (
            "https://evil.example/api/v1/users?after=p2",
            "http://acme.okta.com/api/v1/users?after=p2",
            "https://acme.okta.com.evil.example/api/v1/users?after=p2",
            "https://acme.okta.com@evil.example/api/v1/users?after=p2",
            "https://acme.okta.com:8443/api/v1/users?after=p2",
        ):
            findings, fake = _collect([("/users?", _Response([{"id": "u1", "profile": {}}], next_url=link))])
            self.assertIn("_error", findings, link)
            self.assertNotIn("total_active_users", findings, link)
            self.assertTrue(all(url.startswith(HOST + "/") for url, _ in fake.calls), link)

    def test_a_redirect_is_an_error_not_data(self):
        findings, fake = _collect([("/users?", _Response(status=302))])
        self.assertIn("_error", findings)
        self.assertEqual(len(fake.calls), 1)

        with _creds(), mock.patch.object(okta.requests, "get", return_value=_Response(status=302)):
            ok, _ = okta.test_connection()
        self.assertFalse(ok)


def _factor(factor_type, status="ACTIVE"):
    return {"factorType": factor_type, "status": status}


class FactorClassificationTests(unittest.TestCase):
    def test_weak_factors_alone_are_not_mfa(self):
        for weak in ("sms", "call", "email", "question"):
            self.assertEqual(okta.classify_factors([_factor(weak)]), "weak_only", weak)
        self.assertEqual(okta.classify_factors([_factor("sms"), _factor("question"), _factor("email")]), "weak_only")

    def test_no_active_factor_is_none(self):
        self.assertEqual(okta.classify_factors([]), "none")
        self.assertEqual(okta.classify_factors(None), "none")
        self.assertEqual(okta.classify_factors([_factor("push", status="PENDING_ACTIVATION")]), "none")
        self.assertEqual(okta.classify_factors([_factor("webauthn", status="INACTIVE"), {"status": "ACTIVE"}, "junk"]), "none")

    def test_possession_factors_are_strong(self):
        for strong in ("push", "token:software:totp", "token:hardware", "token", "web"):
            self.assertEqual(okta.classify_factors([_factor(strong)]), "strong", strong)
        self.assertEqual(okta.classify_factors([_factor("sms"), _factor("push")]), "strong")

    def test_origin_bound_factors_are_phishing_resistant(self):
        for best in ("webauthn", "u2f", "signed_nonce"):
            self.assertEqual(okta.classify_factors([_factor(best)]), "phishing_resistant", best)
        self.assertEqual(okta.classify_factors([_factor("sms"), _factor("push"), _factor("webauthn")]), "phishing_resistant")


def _user(uid):
    return {"id": uid, "profile": {"login": f"{uid}@example.org"}}


def _org(factors_by_user, admins=()):
    """Routes for an org whose users have the given factor lists (or an HTTP status)."""
    def factors(url):
        uid = url.split("/users/")[1].split("/")[0]
        value = factors_by_user[uid]
        return _Response(status=value) if isinstance(value, int) else _Response(value)

    def roles(url):
        uid = url.split("/users/")[1].split("/")[0]
        return _Response([{"type": "SUPER_ADMIN"}] if uid in admins else [])

    return [
        ("lastLogin", _Response([])),
        ("/factors", factors),
        ("/roles", roles),
        ("/users?", _Response([_user(uid) for uid in factors_by_user])),
        ("/policies", _Response([])),
        ("/apps", _Response([])),
    ]


class MfaMetricTests(unittest.TestCase):
    def test_only_real_second_factors_count_as_enrolled(self):
        findings, _ = _collect(_org({
            "key": [_factor("webauthn")],
            "push": [_factor("push"), _factor("sms")],
            "sms": [_factor("sms")],
            "question": [_factor("question"), _factor("email")],
            "pending": [_factor("push", status="PENDING_ACTIVATION")],
            "nothing": [],
            "failed": 500,
            "denied": 403,
        }))
        self.assertNotIn("_error", findings)
        self.assertEqual(findings["total_active_users"], 8)
        self.assertEqual(findings["mfa_enrolled_count"], 2)
        self.assertEqual(findings["mfa_enrollment_rate"], 25.0)
        self.assertEqual(findings["mfa_phishing_resistant_count"], 1)
        self.assertEqual(findings["mfa_weak_only_count"], 2)
        self.assertEqual(findings["mfa_none_count"], 2)
        self.assertEqual(findings["mfa_unknown_count"], 2)

    def test_admin_factor_strength_is_reported_by_name(self):
        findings, _ = _collect(_org(
            {
                "root": [_factor("webauthn")],
                "ops": [_factor("push")],
                "legacy": [_factor("sms")],
                "broken": 500,
                "staff": [],
            },
            admins=("root", "ops", "legacy", "broken"),
        ))
        self.assertEqual(findings["admin_count"], 4)
        self.assertEqual(findings["admins_without_mfa"], ["legacy@example.org", "broken@example.org"])
        self.assertEqual(
            findings["admins_without_phishing_resistant_mfa"],
            ["ops@example.org", "legacy@example.org", "broken@example.org"],
        )

    def test_one_factor_lookup_per_user(self):
        _, fake = _collect(_org({"a": [], "b": [], "c": []}, admins=("a",)))
        self.assertEqual(sum(1 for url, _ in fake.calls if url.endswith("/factors")), 3)


class ScoringTests(unittest.TestCase):
    def _score(self, findings):
        from engine import control_mapper, scorer

        evidence = control_mapper.map_okta(findings)["CC6.1"]
        with mock.patch.object(scorer, "_load_controls", return_value=[{"control_id": "CC6.1", "tsc": "CC"}]):
            return scorer.score_all({"CC6.1": evidence}, ["CC"], {})["CC6.1"]

    def test_an_admin_without_mfa_fails_the_control_despite_a_high_rate(self):
        result = self._score({
            "mfa_enrollment_rate": 99.0,
            "admins_without_mfa": ["legacy@example.org"],
            "admins_without_phishing_resistant_mfa": ["legacy@example.org"],
        })
        self.assertNotEqual(result["status"], "compliant")
        self.assertTrue(any("without MFA" in gap and "legacy@example.org" in gap for gap in result["gaps"]))

    def test_weak_only_users_and_unknowns_are_called_out(self):
        result = self._score({"mfa_enrollment_rate": 96.0, "mfa_weak_only_count": 3, "mfa_unknown_count": 2,
                              "admins_without_mfa": [], "admins_without_phishing_resistant_mfa": []})
        self.assertEqual(result["status"], "compliant")
        self.assertTrue(any("SMS" in gap for gap in result["gaps"]))
        self.assertTrue(any("could not be read" in gap for gap in result["gaps"]))

    def test_demo_data_still_scores_compliant(self):
        result = self._score(okta._demo_data())
        self.assertEqual(result["status"], "compliant")


if __name__ == "__main__":
    unittest.main()
