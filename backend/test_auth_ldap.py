import sys
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


def _setup_auth(monkeypatch, *, can_push: bool, read_only: bool = False, readonly_groups=None, push_group: bool = True):
    import importlib

    auth_ldap = importlib.import_module("auth_ldap")

    class _DummyConn:
        pass

    dummy_conn = _DummyConn()

    monkeypatch.setattr(auth_ldap, "_bind_as", lambda username, password: dummy_conn)
    monkeypatch.setattr(auth_ldap, "_search_user", lambda conn, username: {
        "dn": "CN=Alice,OU=Users,DC=example,DC=com",
        "displayName": "Alice Example",
        "mail": "alice@example.com",
        "upn": "alice@example.com",
    })
    monkeypatch.setattr(auth_ldap, "_bind_service", lambda: None)

    push_dn = "CN=Push,OU=Groups,DC=example,DC=com" if push_group else None
    readonly_dns = readonly_groups
    if readonly_dns is None:
        readonly_dns = ["CN=ReadOnly,OU=Groups,DC=example,DC=com"] if read_only else []

    def _fake_is_member(dn, group, conn):
        if push_dn and group == push_dn:
            return can_push
        if group in readonly_dns:
            return read_only
        return False

    monkeypatch.setattr(auth_ldap, "_is_member_of_group", _fake_is_member)
    monkeypatch.setattr(auth_ldap, "PUSH_GROUP_DN", push_dn, raising=False)
    monkeypatch.setattr(auth_ldap, "READONLY_GROUP_DNS", readonly_dns, raising=False)

    return auth_ldap


class _DummyClient:
    host = "127.0.0.1"


class _DummyRequest:
    def __init__(self):
        self.session = {}
        self.client = _DummyClient()


def test_login_rejects_user_without_push_group_membership(monkeypatch):
    auth_ldap = _setup_auth(monkeypatch, can_push=False, read_only=False, readonly_groups=[])

    request = _DummyRequest()
    response = auth_ldap.post_login(request, username="alice", password="pw")

    assert response.status_code == 403
    assert "not authorized" in response.body.decode()
    assert "user" not in request.session


def test_login_succeeds_for_push_group_members(monkeypatch):
    auth_ldap = _setup_auth(monkeypatch, can_push=True)

    request = _DummyRequest()
    response = auth_ldap.post_login(request, username="alice", password="pw")

    assert response.status_code == 302
    assert response.headers["location"] == "/"
    assert request.session["user"]["name"] == "Alice Example"
    assert request.session["user"]["can_push"] is True
    assert request.session["user"].get("read_only") is False


def test_login_allows_read_only_members(monkeypatch):
    auth_ldap = _setup_auth(monkeypatch, can_push=False, read_only=True)

    request = _DummyRequest()
    response = auth_ldap.post_login(request, username="alice", password="pw")

    assert response.status_code == 302
    assert request.session["user"]["can_push"] is False
    assert request.session["user"].get("read_only") is True


def test_login_rejects_when_not_in_any_allowed_group(monkeypatch):
    auth_ldap = _setup_auth(
        monkeypatch,
        can_push=False,
        read_only=False,
        readonly_groups=["CN=ReadOnly,OU=Groups,DC=example,DC=com"],
    )

    request = _DummyRequest()
    response = auth_ldap.post_login(request, username="alice", password="pw")

    assert response.status_code == 403
    assert "not authorized" in response.body.decode()
    assert "user" not in request.session


def test_search_user_checks_multiple_bases(monkeypatch):
    import importlib

    auth_ldap = importlib.reload(importlib.import_module("auth_ldap"))

    class _Attr:
        def __init__(self, value, *, values=None):
            self.value = value
            self.values = values if values is not None else [value]

    class _Entry:
        entry_dn = "CN=Alice,OU=Target,DC=example,DC=com"

        def __init__(self):
            self.displayName = _Attr("Alice Example")
            self.mail = _Attr("alice@example.com")
            self.userPrincipalName = _Attr("alice@example.com")
            self.memberOf = _Attr(None, values=["CN=Push,OU=Groups,DC=example,DC=com"])

    class _DummyConn:
        def __init__(self):
            self.entries = []
            self._search_bases = []

        def search(self, *, search_base, **kwargs):
            self._search_bases.append(search_base)
            if search_base == "OU=Target,DC=example,DC=com":
                self.entries = [_Entry()]
                return True
            self.entries = []
            return False

    dummy_conn = _DummyConn()

    monkeypatch.setattr(auth_ldap, "LDAP_BIND_TEMPLATE", "{username}@example.com", raising=False)
    monkeypatch.setattr(
        auth_ldap,
        "LDAP_SEARCH_BASES",
        ["OU=Users,DC=example,DC=com", "OU=Target,DC=example,DC=com"],
        raising=False,
    )

    result = auth_ldap._search_user(dummy_conn, "alice")

    assert result is not None
    assert dummy_conn._search_bases == [
        "OU=Users,DC=example,DC=com",
        "OU=Target,DC=example,DC=com",
    ]
