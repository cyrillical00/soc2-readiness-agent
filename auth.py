"""
Access control for the SOC2 Readiness Suite.

The deployment's secrets (Okta, AWS, GCP, Jamf and the other connectors,
Supabase, the model API key, the Slack webhook) belong to the operator. A
visitor who has not signed in may use Demo Mode, which runs on synthetic data
only. Everything backed by a secret requires a signed-in user whose address is
on the `allowed_emails` list in the deployment's secrets.

Identity comes only from Streamlit's OIDC sign-in (st.login / st.user).
Modules read secrets through `secret()`, so a session without live access
cannot reach one even if a page forgets to check.
"""

import os

import streamlit as st

# Local development only: see _dev_login_email().
_DEV_LOGIN_ENV = "SOC2_DEV_LOGIN_EMAIL"
_LOOPBACK_ADDRESSES = {"localhost", "127.0.0.1", "::1"}


def _is_email(value) -> bool:
    return isinstance(value, str) and "@" in value


def _claim(user, name, default=None):
    """Read one attribute of st.user. Never raises."""
    try:
        return getattr(user, name)
    except Exception:
        return default


def _verified_email():
    """Email of a user who completed the identity provider's sign-in, or None."""
    user = getattr(st, "user", None)
    if user is None:
        # Name used by the first Streamlit releases that had st.login.
        user = getattr(st, "experimental_user", None)
    if user is None:
        return None
    if _claim(user, "is_logged_in") is not True:
        return None
    email = _claim(user, "email")
    if not _is_email(email):
        return None
    # Providers that report whether the address was verified must say yes.
    if _claim(user, "email_verified", True) is False:
        return None
    return email


def _allowed_emails() -> set:
    """Lower-cased `allowed_emails` secret. Missing or unusable means nobody."""
    try:
        raw = st.secrets.get("allowed_emails", None)
    except Exception:
        return set()
    if isinstance(raw, str):
        raw = [raw]
    try:
        return {x.strip().lower() for x in raw if isinstance(x, str) and x.strip()}
    except Exception:
        return set()


def _server_is_loopback_only() -> bool:
    """True only when Streamlit is bound to this machine's loopback interface."""
    try:
        address = st.get_option("server.address")
    except Exception:
        return False
    return isinstance(address, str) and address.strip().lower() in _LOOPBACK_ADDRESSES


def _dev_login_email():
    """Operator identity for a server that only this machine can reach, or None.

    Needs both SOC2_DEV_LOGIN_EMAIL and a loopback-only server
    (`streamlit run app.py --server.address localhost`). A deployed app listens
    on a routable address, so setting the variable there changes nothing.
    """
    email = os.environ.get(_DEV_LOGIN_ENV, "").strip()
    if not _is_email(email):
        return None
    if not _server_is_loopback_only():
        return None
    return email


def current_user():
    """Email of the user allowed to work with live data, or None."""
    email = _verified_email()
    if email is not None:
        return email if email.strip().lower() in _allowed_emails() else None
    return _dev_login_email()


def live_access_allowed() -> bool:
    """True when this session may use the deployment's secrets."""
    return current_user() is not None


def secret(name: str, default: str = ""):
    """A deployment secret (or environment variable) for an authorised session.

    Any other session gets `default`, exactly as if the secret were not
    configured, so connectors fall back to demo data and the Supabase,
    policy-generation and Slack integrations stay off.
    """
    if not live_access_allowed():
        return default
    try:
        return st.secrets.get(name, os.getenv(name, default))
    except Exception:
        return os.getenv(name, default)


def render_sign_in(key: str = "sign_in") -> None:
    """Offer the identity provider's sign-in, or say why access was refused."""
    if _verified_email() is not None:
        st.error(
            "Your account is not on this deployment's allow list. Ask the operator "
            "to add your address to `allowed_emails`."
        )
        logout = getattr(st, "logout", None)
        if logout is not None and st.button("Sign out", key=f"{key}_out"):
            try:
                logout()
            except Exception:
                pass
        return

    if os.environ.get(_DEV_LOGIN_ENV, "").strip() and not _server_is_loopback_only():
        st.warning(
            f"{_DEV_LOGIN_ENV} is set but ignored: it only works when the server is "
            "bound to this machine (`streamlit run app.py --server.address localhost`)."
        )

    login = getattr(st, "login", None)
    if login is None:
        st.error("This Streamlit version has no sign-in support; install the pinned requirements.")
        return
    if st.button("Sign in", type="primary", key=f"{key}_in"):
        try:
            login()
        except Exception:
            st.error(
                "Sign-in is not configured for this deployment. Add an [auth] section and "
                "`allowed_emails` to its secrets (see .streamlit/secrets.toml.example)."
            )


def require_access() -> None:
    """Page guard. Signed-in users pass; anyone else may only be in Demo Mode."""
    if live_access_allowed():
        return
    if st.session_state.get("demo_mode") is True:
        return
    st.warning("Sign in to work with live data. Demo Mode on the Home page needs no sign-in.")
    render_sign_in(key="page_sign_in")
    st.stop()
    raise PermissionError("Live access requires a signed-in, allow-listed user.")
