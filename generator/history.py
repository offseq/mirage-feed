import json
from datetime import date, timedelta
from pathlib import Path

from .common import DAY, Artifact, Snapshot, dumps

KEEP_DAYS = 90
FIELDS = ("ips_7d", "active_24h", "added", "removed", "cves", "urls", "hashes", "scanners", "anonymizers")


def _carried(prev: Path | None) -> list[dict]:
    path = prev / "history.json" if prev else None
    if not path or not path.is_file():
        return []
    try:
        rows = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        rows = None
    if not isinstance(rows, list):
        return []
    keep = ("day", "generated", *FIELDS)
    return [
        {k: r[k] for k in keep if k in r}
        for r in rows
        if isinstance(r, dict) and isinstance(r.get("day"), str) and DAY.fullmatch(r["day"])
    ]


def entry(s: Snapshot, added: int, removed: int) -> dict:
    pub = s.stats["published"]
    return {
        "day": s.day,
        "generated": s.generated,
        "ips_7d": pub["ips"],
        "active_24h": pub["active_24h"],
        "added": added,
        "removed": removed,
        **{k: pub[k] for k in ("cves", "urls", "hashes", "scanners", "anonymizers")},
    }


def render(s: Snapshot, prev: Path | None, added: int, removed: int) -> Artifact:
    cutoff = (date.fromisoformat(s.day) - timedelta(days=KEEP_DAYS - 1)).isoformat()
    rows = {r["day"]: r for r in _carried(prev) if cutoff <= r["day"] < s.day}
    rows[s.day] = entry(s, added, removed)
    history = [rows[d] for d in sorted(rows)]
    return Artifact("history.json", dumps(history, indent=2), "json", len(history), "90d", ("feeds.offseq.com", "atom"))
