import re
from datetime import timedelta

from . import BASE_URL
from .common import CVE, TOKEN, Snapshot, parse_ts

TOP = 10
SIGNUP = "https://mirage.offseq.com/?auth=signup&intent=premium&utm_source=github&utm_medium=release&utm_campaign=mirage-feed"
MD_META = re.compile(r"([`\[\]()<>#*_\\|!~])")


def defang(value: str) -> str:
    return value.replace("http", "hxxp", 1).replace(".", "[.]")


def md(value) -> str:
    """Escape Markdown and break @mentions with a zero-width joiner."""
    return MD_META.sub(r"\\\1", str(value or "")).replace("@", "@‍")


def _new(records: list[dict], s: Snapshot) -> list[dict]:
    cutoff = parse_ts(s.generated) - timedelta(days=7)
    fresh = [r for r in records if r.get("first_seen") and parse_ts(r["first_seen"]) >= cutoff]
    return sorted(fresh, key=lambda r: -int(r.get("sources", 0)))[:TOP]


def notes(s: Snapshot) -> str:
    pub = s.stats["published"]
    out = [
        f"# Mirage spotlight, week of {s.day}",
        "",
        f"{pub.get('ips', 0):,} attacker IPs, {pub.get('cves', 0)} exploited CVEs and {pub.get('urls', 0)} payload "
        f"URLs in today's feed. Full data: {BASE_URL}/latest/",
    ]
    cves = [c for c in _new(s.lists["cves"], s) if CVE.fullmatch(c["cve"])]
    if cves:
        out += ["", "## CVEs first exploited this week", "", "| CVE | Name | KEV | Sources |", "|---|---|---|---:|"]
        out += [
            f"| {c['cve']} | {md(c.get('name'))} | {'yes' if c['kev'] else 'no'} | {int(c['sources'])} |" for c in cves
        ]
    urls = [u for u in _new(s.lists["urls"], s) if TOKEN.fullmatch(u["kind"])]
    if urls:
        out += ["", "## New payload URLs (defanged)", "", "| URL | Kind | Sources |", "|---|---|---:|"]
        out += [f"| {md(defang(u['url']))} | {u['kind']} | {int(u['sources'])} |" for u in urls]
    fps = sorted(s.lists["fingerprints"], key=lambda f: (-int(f["sources"]), f["value"]))[:TOP]
    if fps:
        out += [
            "",
            "## Most widespread tooling fingerprints",
            "",
            "| Type | Value | Tool | Sources |",
            "|---|---|---|---:|",
        ]
        out += [f"| {f['type']} | {md(f['value'])} | {md(f.get('tool'))} | {int(f['sources'])} |" for f in fps]
    out += ["", f"Data: CC BY 4.0, OffSeq Mirage. TLP:CLEAR. Real-time full feed: {SIGNUP}", ""]
    return "\n".join(out)
