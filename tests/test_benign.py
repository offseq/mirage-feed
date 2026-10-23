import pytest

from generator.benign import domain_ok, path_ok, user_agent_ok


@pytest.mark.parametrize(
    ("domain", "ok"),
    [
        ("evil-payload.example", True),
        ("cdn.evil-payload.example", True),
        ("com", False),
        ("co.uk", False),
        ("github.com", False),
        ("raw.githubusercontent.com", False),
        ("localhost", False),
        ("bad_label.example", False),
    ],
)
def test_domain_ok(domain, ok):
    assert domain_ok(domain) is ok


@pytest.mark.parametrize(
    ("path", "ok"),
    [
        ("/.env", True),
        ("/cgi-bin/luci/;stok=/locale", True),
        ("/", False),
        ("/favicon.ico", False),
        ("/.well-known/security.txt", False),
        ("/a", False),
    ],
)
def test_path_ok(path, ok):
    assert path_ok(path) is ok


@pytest.mark.parametrize(
    ("ua", "ok"),
    [
        ("gobuster/3.8.2", True),
        ("Mozilla/5.0 zgrab/0.x", True),
        (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/5",
            False,
        ),
        ("CCBot/2.0 (https://commoncrawl.org/faq/)", False),
        ("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", False),
        ("  ", False),
    ],
)
def test_user_agent_ok(ua, ok):
    assert user_agent_ok(ua) is ok
