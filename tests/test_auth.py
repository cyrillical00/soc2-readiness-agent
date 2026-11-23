"""Live data and stored assessments must be out of reach without a sign-in."""
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import auth  # noqa: E402

SECRETS = {
    "OKTA_DOMAIN": "acme.okta.com",
    "OKTA_API_TOKEN": "not-a-real-token",
    "SUPABASE_URL": "https://project.example",
    "SUPABASE_KEY": "not-a-real-key",
    "ANTHROPIC_API_KEY": "not-a-real-key",
    "SLACK_WEBHOOK_URL": "https://hooks.example/not-real",
}


class _Stop(BaseException):
    """Stands in for Streamlit's stop signal."""


class _User:
    def __init__(self, **claims):
        self._claims = claims

    def __getattr__(self, name):
        try:
            return self.__dict__["_claims"][name]
        except KeyError:
            raise AttributeError(name) from None


class _FakeStreamlit:
    def __init__(self, user=None, secrets=None, address=None, session_state=None):
        self.user = user if user is not None else _User()
        self.secrets = dict(SECRETS, **(secrets or {}))
        self._address = address
        self.session_state = session_state or {}
        self.rendered = []
        self.login_calls = 0

    def login(self):
        self.login_calls += 1

    def get_option(self, name):
        assert name == "server.address"
        return self._address

    def warning(self, text):
        self.rendered.append(("warning", text))

    def error(self, text):
        self.rendered.append(("error", text))

    def button(self, label, **_):
        self.rendered.append(("button", label))
        return False

    def stop(self):
        raise _Stop()


def _patched(fake, env=None):
    environ = {k: v for k, v in os.environ.items() if k not in SECRETS and k != auth._DEV_LOGIN_ENV}
    environ.update(env or {})
    return mock.patch.object(auth, "st", fake), mock.patch.dict(os.environ, environ, clear=True)


def _signed_in(email="pat@example.org", **claims):
    return _User(is_logged_in=True, email=email, **claims)


class LiveAccessTests(unittest.TestCase):
    def _check(self, fake, env=None):
        p1, p2 = _patched(fake, env)
        with p1, p2:
            return auth.current_user(), auth.secret("OKTA_API_TOKEN"), auth.secret("AWS_REGION", "us-east-1")

    def test_anonymous_session_gets_no_secret(self):
        user, token, region = self._check(_FakeStreamlit())
        self.assertIsNone(user)
        self.assertEqual(token, "")
        self.assertEqual(region, "us-east-1")

    def test_environment_secrets_are_withheld_too(self):
        user, token, _ = self._check(_FakeStreamlit(secrets={"OKTA_API_TOKEN": None}), {"OKTA_API_TOKEN": "from-env"})
        self.assertIsNone(user)
        self.assertEqual(token, "")

    def test_signed_in_and_allow_listed_gets_secrets(self):
        fake = _FakeStreamlit(user=_signed_in("Pat@Example.org"), secrets={"allowed_emails": ["pat@example.org"]})
        user, token, _ = self._check(fake)
        self.assertEqual(user, "Pat@Example.org")
        self.assertEqual(token, "not-a-real-token")

    def test_signed_in_without_an_allow_list_entry_gets_nothing(self):
        for allowed in (None, [], ["lee@example.org"], 7, ""):
            fake = _FakeStreamlit(user=_signed_in(), secrets={"allowed_emails": allowed})
            user, token, _ = self._check(fake)
            self.assertIsNone(user, allowed)
            self.assertEqual(token, "", allowed)

    def test_an_address_without_a_completed_sign_in_is_not_an_identity(self):
        allow = {"allowed_emails": ["pat@example.org"]}
        for user in (
            _User(email="pat@example.org"),
            _User(is_logged_in=False, email="pat@example.org"),
            _User(is_logged_in="true", email="pat@example.org"),
            _User(is_logged_in=True),
            _User(is_logged_in=True, email="pat@example.org", email_verified=False),
        ):
            got, token, _ = self._check(_FakeStreamlit(user=user, secrets=allow))
            self.assertIsNone(got)
            self.assertEqual(token, "")

    def test_session_state_cannot_grant_access(self):
        fake = _FakeStreamlit(session_state={"current_user": "pat@example.org", "live_access": True})
        user, token, _ = self._check(fake)
        self.assertIsNone(user)
        self.assertEqual(token, "")

    def test_dev_login_needs_the_variable_and_a_loopback_only_server(self):
        env = {auth._DEV_LOGIN_ENV: "dev@example.org"}
        user, token, _ = self._check(_FakeStreamlit(address="localhost"), env)
        self.assertEqual(user, "dev@example.org")
        self.assertEqual(token, "not-a-real-token")
        for address in (None, "", "0.0.0.0", "10.0.0.5"):
            user, token, _ = self._check(_FakeStreamlit(address=address), env)
            self.assertIsNone(user, address)
            self.assertEqual(token, "", address)
        user, _, _ = self._check(_FakeStreamlit(address="localhost"))
        self.assertIsNone(user)


class RequireAccessTests(unittest.TestCase):
    def test_anonymous_live_session_is_stopped(self):
        fake = _FakeStreamlit(session_state={"setup_complete": True, "demo_mode": False})
        p1, p2 = _patched(fake)
        with p1, p2, self.assertRaises(_Stop):
            auth.require_access()
        self.assertIn(("button", "Sign in"), fake.rendered)

    def test_anonymous_demo_session_passes_but_still_has_no_secrets(self):
        fake = _FakeStreamlit(session_state={"setup_complete": True, "demo_mode": True})
        p1, p2 = _patched(fake)
        with p1, p2:
            auth.require_access()
            self.assertEqual(auth.secret("SUPABASE_KEY"), "")
            self.assertFalse(auth.live_access_allowed())

    def test_demo_flag_must_be_the_boolean(self):
        fake = _FakeStreamlit(session_state={"demo_mode": "no"})
        p1, p2 = _patched(fake)
        with p1, p2, self.assertRaises(_Stop):
            auth.require_access()

    def test_never_returns_for_a_live_session_that_cannot_be_stopped(self):
        class _NoStop(_FakeStreamlit):
            def stop(self):
                return None

        p1, p2 = _patched(_NoStop())
        with p1, p2, self.assertRaises(PermissionError):
            auth.require_access()

    def test_signed_in_user_passes(self):
        fake = _FakeStreamlit(user=_signed_in(), secrets={"allowed_emails": ["pat@example.org"]})
        p1, p2 = _patched(fake)
        with p1, p2:
            auth.require_access()
        self.assertEqual(fake.rendered, [])


class RealStreamlitTests(unittest.TestCase):
    """Run the real pages under Streamlit's test harness with secrets configured."""

    def setUp(self):
        try:
            from streamlit.testing.v1 import AppTest
        except Exception:  # pragma: no cover - older Streamlit
            self.skipTest("streamlit.testing is not available")
        self.AppTest = AppTest
        environ = {k: v for k, v in os.environ.items() if k not in SECRETS and k != auth._DEV_LOGIN_ENV}
        patcher = mock.patch.dict(os.environ, environ, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

        # Any outbound call from a connector fails the test.
        import requests

        def _no_network(*args, **kwargs):
            raise AssertionError(f"unexpected outbound request: {args}")

        for name in ("get", "post", "request"):
            p = mock.patch.object(requests, name, side_effect=_no_network)
            p.start()
            self.addCleanup(p.stop)

    def _app(self, script, **session_state):
        at = self.AppTest.from_file(str(ROOT / script), default_timeout=60)
        for key, value in SECRETS.items():
            at.secrets[key] = value
        for key, value in session_state.items():
            at.session_state[key] = value
        return at.run()

    def test_home_offers_anonymous_visitors_demo_mode_only(self):
        at = self._app("app.py")
        self.assertFalse(at.exception, [e.value for e in at.exception])
        buttons = {b.label: b for b in at.button}
        self.assertTrue(buttons["Start Assessment →"].disabled)
        self.assertFalse(buttons["🎭 Demo Mode"].disabled)
        self.assertIn("Sign in", buttons)

    def test_a_live_session_without_sign_in_is_sent_back_to_setup(self):
        at = self._app("app.py", setup_complete=True, demo_mode=False, org_name="Acme", audit_type="Type I")
        self.assertFalse(at.exception, [e.value for e in at.exception])
        self.assertFalse(at.session_state["setup_complete"])

    def test_integrations_page_refuses_an_anonymous_live_session(self):
        at = self._app("pages/1_Integrations.py", setup_complete=True, demo_mode=False, org_name="Acme")
        self.assertFalse(at.exception, [e.value for e in at.exception])
        self.assertEqual([b.label for b in at.button], ["Sign in"])

    def test_anonymous_demo_pull_uses_sample_data_and_no_secret(self):
        at = self._app("pages/1_Integrations.py", setup_complete=True, demo_mode=True, org_name="Acme Corp (Demo)")
        self.assertFalse(at.exception, [e.value for e in at.exception])
        pull = [b for b in at.button if "Pull All Data" in b.label]
        self.assertEqual(len(pull), 1)
        pull[0].click().run()
        self.assertFalse(at.exception, [e.value for e in at.exception])
        findings = at.session_state["connector_findings"]
        self.assertEqual(findings["okta"]["_source"], "demo")
        self.assertTrue(all(f.get("_source") == "demo" for f in findings.values()), findings.keys())


if __name__ == "__main__":
    unittest.main()
