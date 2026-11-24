# Partilhado pelos testes de delivery (PL13). Mesmo esquema CSRF que test_delivery_auth_flow.py.
import os
import re

import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:8000")

ALICE_PASS = "tth1mJj5?£58"
BOB_PASS = "De586:Iq6}?!"


def url(path: str) -> str:
    return BASE_URL.rstrip("/") + "/" + path.lstrip("/")


def csrf_headers(for_path: str) -> dict:
    base = BASE_URL.rstrip("/")
    return {"Referer": url(for_path), "Origin": base}


def csrf_from_html(html: str, where: str = "") -> str:
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    if not m:
        m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert m, f"csrf_token not found ({where})"
    return m.group(1)


def new_session() -> requests.Session:
    s = requests.Session()
    s.verify = False
    return s


def login(session: requests.Session, user: str, password: str) -> None:
    page = session.get(url("/login"), allow_redirects=True, timeout=10)
    page.raise_for_status()
    r = session.post(
        url("/login"),
        data={
            "csrf_token": csrf_from_html(page.text, "login"),
            "username": user,
            "password": password,
        },
        headers=csrf_headers("/login"),
        allow_redirects=False,
        timeout=10,
    )
    assert r.status_code in (302, 303), f"login {user}: {r.status_code}"
