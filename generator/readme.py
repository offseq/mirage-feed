import re
from pathlib import Path

from . import BASE_URL, NAME
from .common import Snapshot, parse_ts

START, END = "<!-- stats:start -->", "<!-- stats:end -->"
NONE = "—"


def _n(value) -> str:
    return NONE if value is None else f"{int(value):,}"


def _events(value) -> str:
    if value is None:
        return NONE
    value = int(value)
    for div, unit in ((1_000_000_000, "B"), (1_000_000, "M"), (1_000, "k")):
        if value >= div:
            return f"{value / div:.2f}".rstrip("0").rstrip(".") + f"{unit} events"
    return f"{value:,} events"


def stats_block(s: Snapshot) -> str:
    obs, pub = s.stats.get("observed", {}), s.stats.get("published", {})
    cves = s.lists["cves"]
    kev = sum(1 for c in cves if c.get("kev"))
    cve_label = "CVEs exploited" + (" (all CISA KEV)" if cves and kev == len(cves) else f" ({kev} in CISA KEV)")
    passwords = min(len(s.lists["passwords"]), 100)
    rows = [
        ("Source IPs active in the last 24 h", _n(obs.get("ips")), _n(pub.get("active_24h"))),
        ("Source IPs, 7-day list", NONE, _n(pub.get("ips"))),
        ("IPv4, 30-day list", NONE, _n(pub.get("ips_30d"))),
        ("Networks (ASNs)", _n(obs.get("asns")), _n(pub.get("asns"))),
        ("Countries", _n(obs.get("countries")), _n(pub.get("countries"))),
        (cve_label, _n(obs.get("cves")), _n(pub.get("cves"))),
        ("Payload / download URLs", _n(obs.get("urls")), _n(pub.get("urls"))),
        ("Malware hashes", _n(obs.get("hashes")), _n(pub.get("hashes"))),
        ("Tooling fingerprints", NONE, _n(pub.get("fingerprints"))),
        ("Research scanners (excluded)", NONE, _n(pub.get("scanners"))),
        (
            "Credential pairs tried",
            _n(obs.get("credential_pairs")),
            f"top {passwords} passwords" if passwords else NONE,
        ),
        ("Session transcripts", _events(obs.get("events")), NONE),
    ]
    stamp = parse_ts(s.generated).strftime("%Y-%m-%d %H:%M UTC")
    delay = s.policy.get("delay_hours", 24)
    return "\n".join(
        [
            START,
            "### Today's snapshot",
            "",
            "| | Mirage, last 24 h | In the feed |",
            "|---|---:|---:|",
            *(f"| {a} | {b} | {c} |" for a, b, c in rows),
            "",
            f"<sub>Snapshot {stamp} · lists cover 7 days of activity (30 for ipv4-30d) · "
            f"entries are published {delay} h after first sighting · "
            '<a href="#how-an-ip-gets-listed">methodology</a></sub>',
            END,
        ]
    )


def render_template(template: str) -> str:
    return template.replace("{{REPO}}", NAME).replace("{{BASE}}", BASE_URL)


def update(readme: str, s: Snapshot) -> str:
    pattern = re.compile(re.escape(START) + ".*?" + re.escape(END), re.S)
    if not pattern.search(readme):
        raise ValueError(f"README has no {START} ... {END} block")
    return pattern.sub(lambda _: stats_block(s), readme, count=1)


def write(snapshot: Path, template: Path, readme: Path) -> bool:
    current = readme.read_text(encoding="utf-8") if readme.exists() else None
    text = update(
        current if current is not None else render_template(template.read_text(encoding="utf-8")),
        Snapshot.load(snapshot),
    )
    if text == current:
        return False
    readme.write_text(text, encoding="utf-8")
    return True
