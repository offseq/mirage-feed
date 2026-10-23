import base64
import csv
import gzip
import hashlib
import ipaddress
import json
from pathlib import Path

import pytest

from generator import build, check, readme, spotlight
from generator.common import Snapshot, SnapshotError
from generator.netlist import CANARY, Allowlist
from generator.tables import ATTACKER_COLS

from .conftest import ALLOWLIST, SNAPSHOT


def tree(root: Path) -> dict[str, bytes]:
    return {str(p.relative_to(root)): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


def text_lines(out: Path, rel: str) -> list[str]:
    return (out / rel).read_text().splitlines()


def test_deterministic(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    build.build(SNAPSHOT, a, allowlist=ALLOWLIST)
    build.build(SNAPSHOT, b, allowlist=ALLOWLIST)
    assert tree(a) == tree(b)


def test_plain_lists(out):
    for rel in check.IP_LISTS:
        data = (out / rel).read_bytes()
        assert data.endswith(b"\n") and b"\r" not in data and b"#" not in data
    v4 = text_lines(out, "latest/ipv4-7d.txt")
    assert all(ipaddress.ip_address(ip).version == 4 for ip in v4)
    assert v4 == sorted(v4, key=lambda ip: int(ipaddress.ip_address(ip)))
    assert all(ipaddress.ip_network(n).prefixlen == 64 for n in text_lines(out, "latest/ipv6-7d.txt"))
    assert set(text_lines(out, "latest/ipv4-1d.txt")) <= set(v4) <= set(text_lines(out, "latest/ipv4-30d.txt"))
    assert text_lines(out, "latest/ipv4-7d-cidr32.txt") == [f"{ip}/32" for ip in v4]
    assert text_lines(out, "latest/passwords-top100.txt")[0] == "123456"


def test_control_characters_dropped(out):
    assert "bad\tagent" not in (out / "latest/user-agents-7d.txt").read_text()


def test_top_lists_rank_by_confidence(snapshot_raw):
    s = Snapshot(snapshot_raw)
    top = {r["ip"] for r in s.ranked_v4(5)}
    v4 = [r for r in snapshot_raw["ips"] if ":" not in r["ip"] and "/" not in r["ip"] and r["window"] != "30d"]
    best = sorted(v4, key=lambda r: (-r["confidence"], ipaddress.ip_address(r["ip"])))[:5]
    assert top == {r["ip"] for r in best}


def test_csv_files_parse_and_are_injection_safe(out):
    for rel in (
        "latest/attackers-7d.csv",
        "latest/cves-7d.csv",
        "latest/fingerprints.csv",
        "latest/hassh.csv",
        "latest/crowdsec/mirage-7d.csv",
        "latest/defender/defender-top500.csv",
        "latest/attackers-ipv4-7d.csv",
    ):
        with (out / rel).open(newline="") as fh:
            rows = list(csv.reader(fh))
        width = len(rows[0])
        assert all(len(r) == width for r in rows), rel
        assert not any(c.startswith(("=", "+", "-", "@", "\t", "\r")) for r in rows[1:] for c in r), rel
    with (out / "latest/attackers-7d.csv").open(newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert tuple(rows[0]) == ATTACKER_COLS
    assert any(r["as_org"] == '\'=HYPERLINK("http://x")' for r in rows)
    assert any(r["as_org"] == "'-Test Transit" for r in rows)


def test_records_match_schema(out):
    raw = (out / "latest/records-7d.ndjson.gz").read_bytes()
    assert raw[4:8] == b"\0\0\0\0"
    recs = [json.loads(line) for line in gzip.decompress(raw).splitlines()]
    assert {r["type"] for r in recs} == {"ipv4", "ipv6", "url", "domain", "sha256"}
    assert check.check_schema(out) == []


def test_zeek_intel(out):
    lines = text_lines(out, "latest/zeek/mirage.intel")
    assert lines[0] == "#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\tmeta.url"
    rows = [line.split("\t") for line in lines[1:]]
    assert all(len(r) == 5 for r in rows)
    assert all("://" not in r[0] for r in rows if r[1] == "Intel::URL")
    assert {r[1] for r in rows} >= {"Intel::ADDR", "Intel::SUBNET", "Intel::URL", "Intel::DOMAIN"}


def test_suricata(out):
    for line in text_lines(out, "latest/suricata/mirage-iprep.list"):
        ip, cat, score = line.split(",")
        ipaddress.ip_network(ip)
        assert cat == "1" and 1 <= int(score) <= 127
    uas = text_lines(out, "latest/suricata/datasets/uas.lst")
    assert base64.b64decode(uas[0]).decode() == "=cmd|' /C calc'!A0"
    rules = (out / "latest/suricata/mirage.rules").read_text()
    assert "sid:1900001;" in rules and "iprep:src,MirageAttacker" in rules


def test_firewall_formats(out):
    nft = (out / "latest/nft/mirage.nft").read_text()
    assert nft.index("flush set inet mirage_feed bad4") < nft.index("add element inet mirage_feed bad4")
    rsc = text_lines(out, "latest/mikrotik/mirage-7d.rsc")
    assert rsc[0] == "/ip firewall address-list" and "/ipv6 firewall address-list" in rsc
    assert "on-error={ set [find list=mirage-feed address=198.51.100.2] timeout=7d }" in rsc[1]
    assert "add rule inet mirage_feed forward ip saddr @bad4 drop" in nft
    ipset = text_lines(out, "latest/ipset/mirage.ipset")
    assert "swap mirage4-tmp mirage4" in ipset and "destroy mirage6-tmp" in ipset
    with (out / "latest/defender/defender-top500.csv").open(newline="") as fh:
        assert {r["GenerateAlert"] for r in csv.DictReader(fh)} == {"True"}


def test_spotlight_escapes_markdown(snapshot_raw):
    snapshot_raw["cves"][0]["name"] = "[x](http://e) @team <b>"
    snapshot_raw["cves"][0]["first_seen"] = "2026-10-22T00:00:00Z"
    text = spotlight.notes(Snapshot(snapshot_raw))
    assert "\\[x\\]\\(http://e\\) @\u200dteam \\<b\\>" in text
    assert "](" not in text and "hxxp" in text


def test_stix_bundle(out):
    bundle = json.loads((out / "latest/stix/mirage.json").read_text())
    ids = [o["id"] for o in bundle["objects"]]
    assert len(ids) == len(set(ids))
    patterns = [o["pattern"] for o in bundle["objects"] if o["type"] == "indicator"]
    assert "[url:value = 'http://payload.example/bins/x86?arch=\\'mips\\'']" in patterns
    assert "[url:value = 'http://203.0.113.200/a\\\\b.sh']" in patterns
    assert check.check_stix(out) == []


def test_misp_feed(out):
    manifest = json.loads((out / "misp/manifest.json").read_text())
    hashes = [line.split(",") for line in text_lines(out, "misp/hashes.csv")]
    expected = []
    for event_uuid in manifest:
        event = json.loads((out / f"misp/{event_uuid}.json").read_text())["Event"]
        assert event["uuid"] == event_uuid and event["Tag"][0]["name"] == "tlp:clear"
        for attr in event["Attribute"]:
            assert attr["to_ids"] == (attr["type"] in ("ip-src", "url", "domain", "sha256"))
            expected.append([hashlib.md5(attr["value"].encode()).hexdigest(), event_uuid])
    assert sorted(hashes) == sorted(expected)


def test_misp_keeps_week_and_prunes_ips(tmp_path, snapshot_raw):
    prev = None
    for day in range(1, 12):
        snap = {**snapshot_raw, "day": f"2026-10-{day:02d}", "generated": f"2026-10-{day + 1:02d}T03:05:00Z"}
        if day == 11:
            snap["ips"] = [r for r in snapshot_raw["ips"] if r["ip"] != "203.0.113.2"]
        path = tmp_path / "snap.json"
        path.write_text(json.dumps(snap))
        out = tmp_path / f"out{day}"
        build.build(path, out, prev, ALLOWLIST)
        prev = out
    manifest = json.loads((prev / "misp/manifest.json").read_text())
    assert sorted(m["date"] for m in manifest.values()) == [f"2026-10-{d:02d}" for d in range(4, 12)]
    for event_uuid in manifest:
        attrs = json.loads((prev / f"misp/{event_uuid}.json").read_text())["Event"]["Attribute"]
        assert "203.0.113.2" not in {a["value"] for a in attrs if a["type"] == "ip-src"}
    assert check.check_ips(prev, Allowlist(ALLOWLIST), Allowlist(CANARY)) == []


def test_snapshot_loader_filters(snapshot_raw):
    s = Snapshot(snapshot_raw)
    assert [r["confidence"] for r in s.lists["ips"] if r["ip"] == "203.0.113.5"] != [1]
    assert len({r["ip"] for r in s.lists["ips"]}) == len(s.lists["ips"])
    assert "github.com" not in {d["domain"] for d in s.lists["domains"]}
    assert {"/", "/robots.txt", "/a"}.isdisjoint(p["value"] for p in s.lists["paths"])
    assert not any("Chrome/129" in u["value"] for u in s.lists["user_agents"])


@pytest.mark.parametrize(
    "change",
    [
        {"day": "2026-10-23\nBASH_ENV=/tmp/x"},
        {"day": "2026-10-20"},
        {"day": "2026-13-01"},
        {"generated": "2026-10-24 03:05"},
        {"ips": []},
        {"scanners": None},
    ],
)
def test_snapshot_rejects(snapshot_raw, change):
    with pytest.raises(SnapshotError):
        Snapshot({**snapshot_raw, **change})


@pytest.mark.parametrize(
    "field, value",
    [("ip", 3405803781), ("sensors", 2), ("networks", 1), ("confidence", 101), ("window", "90d")],
)
def test_snapshot_rejects_bad_ip_record(snapshot_raw, field, value):
    snapshot_raw["ips"][0][field] = value
    with pytest.raises(SnapshotError):
        Snapshot(snapshot_raw)


def test_snapshot_drops_format_characters(snapshot_raw):
    snapshot_raw["urls"][0]["url"] += "\u200b"
    snapshot_raw["paths"][0]["value"] += "\u2028"
    s = Snapshot(snapshot_raw)
    assert len(s.lists["urls"]) == len(snapshot_raw["urls"]) - 1


def test_stats_are_whitelisted(snapshot_raw):
    snapshot_raw["stats"]["observed"]["secret_sensor_ip"] = "192.0.2.1"
    snapshot_raw["stats"]["countries"].append({"country": "<script>", "ips": 1})
    s = Snapshot(snapshot_raw)
    assert "secret_sensor_ip" not in s.stats["observed"]
    assert all(c["country"] != "<script>" for c in s.stats["countries"])


def test_feed_index_and_sums(out):
    feed = json.loads((out / "feed.json").read_text())
    by_path = {f["path"]: f for f in feed["files"]}
    assert by_path["latest/ipv4-7d.txt"]["count"] == len(text_lines(out, "latest/ipv4-7d.txt"))
    for f in feed["files"]:
        assert hashlib.sha256((out / f["path"]).read_bytes()).hexdigest() == f["sha256"]
    sums = text_lines(out, "SHA256SUMS")
    assert [line.split("  ", 1)[1] for line in sums] == sorted(p for p in tree(out) if p != "SHA256SUMS")
    assert json.loads((out / "stats.json").read_text()) == Snapshot.load(SNAPSHOT).stats
    assert (out / "schema/record.schema.json").read_bytes() == check.RECORD_SCHEMA.read_bytes()


def test_readme_stats_idempotent(tmp_path):
    template = Path(__file__).parents[1] / "docs/README.template.md"
    target = tmp_path / "README.md"
    assert readme.write(SNAPSHOT, template, target)
    first = target.read_text()
    assert "{{" not in first and "Snapshot 2026-10-24 03:05 UTC" in first
    assert "| Source IPs active in the last 24 h | 8,715 |" in first
    assert not readme.write(SNAPSHOT, template, target)
    assert target.read_text() == first
    assert first.split(readme.END)[1] == readme.render_template(template.read_text()).split(readme.END)[1]
