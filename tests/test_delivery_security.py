# Testes dinâmicos no stack de delivery (ver PL13). Corre com APP_BASE_URL=https://localhost:8433
from delivery_helpers import (
    ALICE_PASS,
    BOB_PASS,
    csrf_from_html,
    csrf_headers,
    login,
    new_session,
    url,
)


def test_documents_without_login_redirects():
    r = new_session().get(url("/documents"), allow_redirects=False, timeout=10)
    assert r.status_code in (302, 303)


def test_alice_cannot_open_admin_users():
    s = new_session()
    login(s, "alice", ALICE_PASS)
    r = s.get(url("/admin/users"), allow_redirects=False, timeout=10)
    assert r.status_code == 403


def test_download_without_login_redirects():
    r = new_session().get(url("/documents/1/download"), allow_redirects=False, timeout=10)
    assert r.status_code in (302, 303)


def test_bob_cannot_share_foreign_document():
    s = new_session()
    login(s, "bob", BOB_PASS)
    page = s.get(url("/documents/1/share"), timeout=10)
    page.raise_for_status()
    r = s.post(
        url("/documents/1/share"),
        data={"csrf_token": csrf_from_html(page.text, "share"), "uname": "alice"},
        headers=csrf_headers("/documents/1/share"),
        allow_redirects=False,
        timeout=10,
    )
    assert r.status_code == 403


def test_other_user_cannot_view_alice_document_page():
    alice = new_session()
    login(alice, "alice", ALICE_PASS)
    bob = new_session()
    login(bob, "bob", BOB_PASS)

    for doc_id in (1, 2, 3):
        ar = alice.get(url(f"/documents/{doc_id}"), allow_redirects=False, timeout=10)
        if ar.status_code != 200:
            continue
        br = bob.get(url(f"/documents/{doc_id}"), allow_redirects=False, timeout=10)
        assert br.status_code in (403, 404)
