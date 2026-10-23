import gzip
import io
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .common import Snapshot, parse_ts

DEFAULT_URL = "https://mirage.offseq.com/api/feed/community"
TOKEN_ENV = "MIRAGE_FEED_TOKEN"
ATTEMPTS = 5
TIMEOUT = 60
MAX_BODY = 64 << 20
MAX_JSON = 256 << 20
MAX_AGE = timedelta(hours=36)
LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")


class FetchError(RuntimeError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise FetchError(f"refusing redirect ({code}) from {req.full_url}")


_OPENER = urllib.request.build_opener(_NoRedirect)


def _check_url(url: str) -> None:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" and not (parts.scheme == "http" and parts.hostname in LOCAL_HOSTS):
        raise FetchError(f"refusing non-https URL {url}")


def _get(url: str, token: str) -> bytes:
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
            "User-Agent": "mirage-feed-generator",
        },
    )
    with _OPENER.open(req, timeout=TIMEOUT) as resp:
        body = resp.read(MAX_BODY + 1)
        gzipped = resp.headers.get("Content-Encoding") == "gzip"
    if len(body) > MAX_BODY:
        raise FetchError(f"response larger than {MAX_BODY >> 20} MB")
    if gzipped:
        body = gzip.GzipFile(fileobj=io.BytesIO(body)).read(MAX_JSON + 1)
    if len(body) > MAX_JSON:
        raise FetchError(f"decompressed response larger than {MAX_JSON >> 20} MB")
    return body


def fetch(url: str, dest: Path, day: str | None = None, sleep=time.sleep, now: datetime | None = None) -> Snapshot:
    _check_url(url)
    token = os.environ.get(TOKEN_ENV, "").strip()
    if not token:
        raise FetchError(f"{TOKEN_ENV} is not set")
    if day:
        url = f"{url}?{urllib.parse.urlencode({'day': day})}"
    last: Exception | None = None
    for attempt in range(ATTEMPTS):
        try:
            body = _get(url, token)
            break
        except urllib.error.HTTPError as exc:
            if exc.code < 500 and exc.code != 429:
                raise FetchError(f"GET {url}: HTTP {exc.code} {exc.reason}") from exc
            last = exc
        except (urllib.error.URLError, TimeoutError, OSError, EOFError) as exc:
            last = exc
        if attempt < ATTEMPTS - 1:
            sleep(5 * 2**attempt)
    else:
        raise FetchError(f"GET {url}: giving up after {ATTEMPTS} attempts: {last}")
    try:
        snapshot = Snapshot(json.loads(body))
    except ValueError as exc:
        raise FetchError(f"GET {url}: invalid snapshot: {exc}") from exc
    if day and snapshot.day != day:
        raise FetchError(f"asked for day {day}, got {snapshot.day}")
    if not day and (now or datetime.now(UTC)) - parse_ts(snapshot.generated) > MAX_AGE:
        raise FetchError(
            f"snapshot generated {snapshot.generated} is older than {MAX_AGE.total_seconds() / 3600:.0f} h"
        )
    dest.write_bytes(body)
    return snapshot
