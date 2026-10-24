import json
from pathlib import Path

from .common import Artifact, Snapshot, ip_key, lines

EDL = ("pfsense", "opnsense", "fortigate", "palo-alto", "crowdsec", "ipset")
V4_7D = "latest/ipv4-7d.txt"
ADDED = "latest/ipv4-added-1d.txt"
REMOVED = "latest/ipv4-removed-1d.txt"


def _txt(path: str, values: list[str], window: str | None, consumers=()) -> Artifact:
    return Artifact(f"latest/{path}", lines(values), "txt", len(values), window, tuple(consumers))


def _values(records, key: str) -> list[str]:
    return sorted({r[key] for r in records})


def _top_passwords(s: Snapshot) -> list[str]:
    ranked = sorted(s.lists["passwords"], key=lambda r: (-int(r["sources"]), r["value"]))
    return [r["value"] for r in ranked[:100]]


def _set(prev: Path, rel: str) -> set[str]:
    path = prev / rel
    return set(path.read_text(encoding="utf-8").split()) if path.is_file() else set()


def _same_day(prev: Path, day: str) -> bool:
    try:
        return json.loads((prev / "feed.json").read_text(encoding="utf-8")).get("day") == day
    except (OSError, ValueError, AttributeError):
        return False


def _diff(v4_7d: list[str], prev: Path | None, day: str) -> tuple[list[str], list[str]]:
    if not prev or not (prev / V4_7D).is_file():
        return [], []
    old, new = _set(prev, V4_7D), set(v4_7d)
    if _same_day(prev, day):
        # A rebuild of the same day diffs against the build before it, so its change list is not lost.
        old = (old - _set(prev, ADDED)) | _set(prev, REMOVED)
    return sorted(new - old, key=ip_key), sorted(old - new, key=ip_key)


def render(s: Snapshot, prev: Path | None = None) -> list[Artifact]:
    v4_7d = [r["ip"] for r in s.blockable("7d", 4)]
    v4_30d = [r["ip"] for r in s.blockable("30d", 4)]
    added, removed = _diff(v4_7d, prev, s.day)
    scanners = sorted((r["ip"] for r in s.lists["scanners"]), key=ip_key)
    scan4 = [ip for ip in scanners if ":" not in ip]
    scan6 = [ip for ip in scanners if ":" in ip]
    return [
        _txt("ipv4-1d.txt", [r["ip"] for r in s.blockable("1d", 4)], "1d", EDL),
        _txt("ipv4-7d.txt", v4_7d, "7d", EDL),
        _txt("ipv4-30d.txt", v4_30d, "30d", EDL),
        _txt("ipv6-7d.txt", [r["ip"] for r in s.blockable("7d", 6)], "7d", EDL),
        _txt("ipv4-top1k.txt", [r["ip"] for r in s.ranked_v4(1000)], "7d", EDL),
        _txt("ipv4-top10k.txt", [r["ip"] for r in s.ranked_v4(10000)], "7d", EDL),
        _txt("ipv4-7d-cidr32.txt", [f"{ip}/32" for ip in v4_7d], "7d", ("aws-waf",)),
        _txt("ipv4-added-1d.txt", added, "1d", ("siem", "change-review")),
        _txt("ipv4-removed-1d.txt", removed, "1d", ("siem", "change-review")),
        _txt("anonymizers-7d.txt", [r["ip"] for r in s.anonymizers()], "7d", ("siem", "enrichment")),
        _txt("urls-7d.txt", _values(s.lists["urls"], "url"), "7d", ("proxy", "edl", "siem")),
        _txt("domains-7d.txt", _values(s.lists["domains"], "domain"), "7d", ("dns-rpz", "edl", "siem")),
        _txt("hashes-sha256-30d.txt", _values(s.lists["hashes"], "sha256"), "30d", ("edr", "siem")),
        _txt("user-agents-7d.txt", _values(s.lists["user_agents"], "value"), "7d", ("hunting",)),
        _txt("paths-7d.txt", _values(s.lists["paths"], "value"), "7d", ("hunting",)),
        _txt("passwords-top100.txt", _top_passwords(s), None, ("password-policy",)),
        _txt("known-scanners-ipv4.txt", scan4, None, ("allowlist",)),
        _txt("known-scanners-ipv6.txt", scan6, None, ("allowlist",)),
    ]
