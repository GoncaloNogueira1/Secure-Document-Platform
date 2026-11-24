import os
import re

import requests
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings for self-signed certificates
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:8000")


def _url(path: str) -> str:
    return BASE_URL.rstrip("/") + "/" + path.lstrip("/")


def _csrf_headers(path: str) -> dict[str, str]:
    return {
        "Referer": _url(path),
        "Origin": BASE_URL.rstrip("/"),
    }


def _csrf_token_from_html(html: str, context: str) -> str:
    match = re.search(
        r'name="csrf_token"\s+value="([^"]+)"',
        html,
    )
    if not match:
        match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match, f"CSRF token not found ({context})"
    return match.group(1)


def _csrf_token_from_login_page(session: requests.Session) -> str:
    page = session.get(_url("/login"), allow_redirects=True, timeout=10)
    page.raise_for_status()
    return _csrf_token_from_html(page.text, "login page")


def _same_origin_headers(referer_path: str) -> dict[str, str]:
    """
       HTTPS POST requests may require a valid Referer header. 
       Browsers send that automatically when submitting a same-origin form, but requests.Session().post(...) does not 
    """
    base = BASE_URL.rstrip("/")
    return {
        "Referer": _url(referer_path),
        "Origin": base,
    }


def test_login_logout_flow():
    """
    Delivery-stage integration test.

    Verifies the authentication flow against a running deployment:
    1. Login with valid credentials
    2. Access a protected page
    3. Logout
    4. Verify access is revoked
    """

    session = requests.Session()
    session.verify = False  # Disable SSL verification for self-signed certificates

    # ------------------------------------------------------------
    # Login
    # ------------------------------------------------------------
    csrf = _csrf_token_from_login_page(session)
    login_resp = session.post(
        _url("/login"),
        data={
            "csrf_token": csrf,
            "username": "alice",
            "password": "tth1mJj5?£58",
        },
        headers=_csrf_headers("/login"),
        allow_redirects=False,
        timeout=10,
    )

    assert login_resp.status_code in (302, 303), (
        f"Login failed unexpectedly: {login_resp.status_code}"
    )

    # ------------------------------------------------------------
    # Access protected page
    # ------------------------------------------------------------
    documents_resp = session.get(
        _url("/documents"),
        allow_redirects=False,
        timeout=10,
    )

    assert documents_resp.status_code == 200, (
        "Authenticated user cannot access /documents"
    )

    logout_csrf = _csrf_token_from_html(documents_resp.text, "documents page")

    # ------------------------------------------------------------
    # Logout
    # ------------------------------------------------------------
    logout_resp = session.post(
        _url("/logout"),
        data={"csrf_token": logout_csrf},
        headers=_csrf_headers("/documents"),
        allow_redirects=False,
        timeout=10,
    )

    assert logout_resp.status_code in (302, 303), (
        f"Logout failed unexpectedly: {logout_resp.status_code}\n"
        f"Response body:\n{login_resp.text[:1000]}"
    )

    # ------------------------------------------------------------
    # Verify session is invalidated
    # ------------------------------------------------------------
    after_logout = session.get(
        _url("/documents"),
        allow_redirects=False,
        timeout=10,
    )

    assert after_logout.status_code in (302, 303), (
        "Protected page still accessible after logout"
    )
