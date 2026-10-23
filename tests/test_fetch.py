import json
import urllib.error
from datetime import UTC, datetime

import pytest

from generator import fetch

from .conftest import SNAPSHOT

NOW = datetime(2026, 10, 24, 6, 0, tzinfo=UTC)


def http_error(code):
    return urllib.error.HTTPError("https://x", code, "err", {}, None)


@pytest.fixture(autouse=True)
def token(monkeypatch):
    monkeypatch.setenv(fetch.TOKEN_ENV, "t0ken")


def fake_get(monkeypatch, responses):
    calls = []

    def get(url, token):
        calls.append((url, token))
        item = responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    monkeypatch.setattr(fetch, "_get", get)
    return calls


def test_retries_then_succeeds(monkeypatch, tmp_path):
    calls = fake_get(monkeypatch, [http_error(503), urllib.error.URLError("reset"), SNAPSHOT.read_bytes()])
    sleeps = []
    snap = fetch.fetch("https://x/api", tmp_path / "s.json", "2026-10-23", sleep=sleeps.append)
    assert snap.day == "2026-10-23" and sleeps == [5, 10]
    assert calls[0] == ("https://x/api?day=2026-10-23", "t0ken")
    assert (tmp_path / "s.json").read_bytes() == SNAPSHOT.read_bytes()


def test_auth_failure_is_not_retried(monkeypatch, tmp_path):
    calls = fake_get(monkeypatch, [http_error(401)])
    with pytest.raises(fetch.FetchError, match="HTTP 401"):
        fetch.fetch("https://x/api", tmp_path / "s.json", sleep=lambda _: None, now=NOW)
    assert len(calls) == 1


def test_gives_up(monkeypatch, tmp_path):
    fake_get(monkeypatch, [http_error(502)] * fetch.ATTEMPTS)
    with pytest.raises(fetch.FetchError, match="giving up"):
        fetch.fetch("https://x/api", tmp_path / "s.json", sleep=lambda _: None)


def test_wrong_schema_rejected(monkeypatch, tmp_path):
    body = json.dumps({**json.loads(SNAPSHOT.read_text()), "schema": "mirage-community/2"}).encode()
    fake_get(monkeypatch, [body])
    with pytest.raises(fetch.FetchError, match="unexpected schema"):
        fetch.fetch("https://x/api", tmp_path / "s.json", sleep=lambda _: None, now=NOW)
    assert not (tmp_path / "s.json").exists()


def test_missing_token(monkeypatch, tmp_path):
    monkeypatch.delenv(fetch.TOKEN_ENV)
    with pytest.raises(fetch.FetchError, match="not set"):
        fetch.fetch("https://x/api", tmp_path / "s.json")


def test_stale_snapshot_rejected(monkeypatch, tmp_path):
    fake_get(monkeypatch, [SNAPSHOT.read_bytes()])
    with pytest.raises(fetch.FetchError, match="older than 36 h"):
        fetch.fetch("https://x/api", tmp_path / "s.json", sleep=lambda _: None, now=datetime(2026, 10, 26, tzinfo=UTC))


@pytest.mark.parametrize("url", ["http://mirage.example/api", "ftp://x/api"])
def test_non_https_rejected(tmp_path, url):
    with pytest.raises(fetch.FetchError, match="non-https"):
        fetch.fetch(url, tmp_path / "s.json")


def test_redirect_refused(tmp_path):
    import http.server
    import threading

    class Redirect(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", "https://elsewhere.example/")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Redirect)
    threading.Thread(target=server.handle_request, daemon=True).start()
    with pytest.raises(fetch.FetchError, match="refusing redirect"):
        fetch.fetch(f"http://127.0.0.1:{server.server_port}/api", tmp_path / "s.json", sleep=lambda _: None)
    server.server_close()
