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
        ("Source IPs active in the last 24 h", _n(obs.get("ips")), _n(pub.get("active_24h")), "24 h"),
        ("Source IPs", NONE, _n(pub.get("ips")), "7 days"),
        ("VPN / Tor exits (only in `anonymizers-7d.txt`)", NONE, _n(pub.get("anonymizers")), "7 days"),
        ("IPv4 addresses (`ipv4-30d.txt`)", NONE, _n(len(s.blockable("30d", 4))), "30 days"),
        ("Networks (ASNs)", _n(obs.get("asns")), _n(pub.get("asns")), "7 days"),
        ("Countries", _n(obs.get("countries")), _n(pub.get("countries")), "7 days"),
        (cve_label, _n(obs.get("cves")), _n(pub.get("cves")), "7 days"),
        ("Payload / download URLs", _n(obs.get("urls")), _n(pub.get("urls")), "7 days"),
        ("Malware hashes", _n(obs.get("hashes")), _n(pub.get("hashes")), "7 days"),
        ("Tooling fingerprints (JA4+, HASSH)", NONE, _n(pub.get("fingerprints")), "7 days"),
        ("Research scanners (excluded)", NONE, _n(pub.get("scanners")), "7 days"),
        (
            "Credential pairs tried",
            _n(obs.get("credential_pairs")),
            f"top {passwords} passwords" if passwords else NONE,
            "7 days",
        ),
        ("Events", _events(obs.get("events")), NONE, NONE),
    ]
    stamp = parse_ts(s.generated).strftime("%Y-%m-%d %H:%M UTC")
    delay = s.policy.get("delay_hours", 24)
    return "\n".join(
        [
            START,
            "### Today's snapshot",
            "",
            "| | Observed by Mirage, last 24 h | In the feed | Feed window |",
            "|---|---:|---:|---|",
            *(f"| {a} | {b} | {c} | {d} |" for a, b, c, d in rows),
            "",
            f"<sub>Snapshot {stamp} · the observed column counts everything the fleet saw in the 24 h before the "
            f"snapshot; the feed column counts what passed the listing rules over the window shown · "
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
