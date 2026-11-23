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


if __name__ == "__main__":
    unittest.main()
