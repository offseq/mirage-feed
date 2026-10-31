import gzip
import ipaddress
import json
import shutil

import pytest

from generator import check
from generator.__main__ import main
from generator.netlist import DEFAULT_ALLOWLIST, Allowlist

from .conftest import ALLOWLIST

LEAK = ["sensor-[0-9]{3}\\.internal", "zz_marker_[0-9a-f]{8}"]


def run(out, prev=None, **kw):
    kw.setdefault("bootstrap", prev is None)
    return check.run(out, prev, ALLOWLIST, leak_patterns=LEAK, leak_literals=["192.0.2.250"], **kw)


def text_lines(out, rel):
    return (out / rel).read_text().splitlines()


def append(path, line):
    with path.open("a") as fh:
        fh.write(line + "\n")


def test_fixture_passes(out):
    assert run(out) == []


def test_production_allowlist_blocks_documentation_ranges(out):
    errors = check.run(out, None, DEFAULT_ALLOWLIST, bootstrap=True)
    assert errors and all("overlaps allowlisted" in e for e in errors)


def test_production_allowlist_covers_first_party_ranges():
    allow = Allowlist(DEFAULT_ALLOWLIST)
    for ip in ("8.8.8.8", "1.1.1.1", "140.82.112.3", "13.107.42.14", "198.41.0.4", "17.253.144.10", "151.101.1.69"):
        assert allow.hit(ipaddress.ip_network(ip)), ip
    assert allow.hit(ipaddress.ip_network("2620:fe::/64"))
    for customer_cloud in ("52.94.236.248", "172.104.0.1", "34.120.0.1"):
        assert not allow.hit(ipaddress.ip_network(customer_cloud)), customer_cloud


@pytest.mark.parametrize("bad", ["10.20.30.40", "192.168.1.1"])
def test_allowlisted_ip_trips(out, bad):
    append(out / "latest/ipv4-7d.txt", bad)
    assert any(f"ipv4-7d.txt: {bad} overlaps allowlisted" in e for e in run(out))


@pytest.mark.parametrize("canary", ["140.82.112.3", "8.8.8.8"])
def test_canary_trips(out, canary):
    append(out / "latest/ipv4-30d.txt", canary)
    assert any(f"canary address {canary}" in e for e in run(out))


def test_wide_prefix_trips(out):
    append(out / "latest/ipv4-7d-cidr32.txt", "203.0.113.0/24")
    append(out / "latest/ipv6-7d.txt", "2001:db8:aa::/48")
    errors = run(out)
    assert any("203.0.113.0/24" in e for e in errors)
    assert any("2001:db8:aa::/48" in e for e in errors)


def test_duplicate_trips(out):
    first = (out / "latest/ipv4-7d.txt").read_text().splitlines()[0]
    append(out / "latest/ipv4-7d.txt", first)
    assert any(f"duplicate entry {first}" in e for e in run(out))


def test_misp_ip_is_gated(out):
    event = next(p for p in (out / "misp").glob("*.json") if p.name != "manifest.json")
    body = json.loads(event.read_text())
    body["Event"]["Attribute"].append({"type": "ip-src", "value": "10.0.0.1"})
    event.write_text(json.dumps(body))
    assert any("10.0.0.1 overlaps allowlisted" in e for e in run(out))


@pytest.mark.parametrize("bad", ["0.0.0.0/0", "192.0.2.0/24", "2001:db8::/32"])
def test_scanner_width_trips(out, bad):
    rel = "latest/known-scanners-ipv6.txt" if ":" in bad else "latest/known-scanners-ipv4.txt"
    append(out / rel, bad)
    assert any(bad in e and "only canonical" in e for e in run(out))


def test_scanner_also_attacker_trips(out):
    append(out / "latest/known-scanners-ipv4.txt", "198.51.100.2")
    assert any("also listed as an attacker" in e for e in run(out))


def test_attacker_turned_scanner_may_be_in_the_removal_list(out):
    append(out / "latest/known-scanners-ipv4.txt", "198.51.100.251")
    append(out / "latest/ipv4-removed-1d.txt", "198.51.100.251")
    assert check.check_scanners(out, Allowlist(check.CANARY)) == []


@pytest.mark.parametrize(
    "payload",
    ["http://198.51.100.9/sensor-042.internal/x", "SENSOR-042.INTERNAL", "sensor%2d042.internal",
     "sens​or-042.internal", "zz_marker_0a1b2c3d", "198.51.100.9/?h=192.0.2.250"],
)  # fmt: skip
def test_leak_patterns_trip(out, payload):
    append(out / "latest/urls-7d.txt", payload)
    errors = run(out)
    assert "leak in latest/urls-7d.txt" in errors
    assert not any("sensor-042" in e.casefold() or "zz_marker" in e for e in errors)


def test_leak_in_gzip_and_base64_trips(out):
    path = out / "latest/records-7d.ndjson.gz"
    path.write_bytes(gzip.compress(gzip.decompress(path.read_bytes()) + b'{"x":"zz_marker_00112233"}\n'))
    append(out / "latest/suricata/datasets/uas.lst", "c2Vuc29yLTA0Mi5pbnRlcm5hbA==")
    errors = run(out)
    assert "leak in latest/records-7d.ndjson.gz" in errors
    assert "leak in latest/suricata/datasets/uas.lst" in errors


def test_leak_rules_required(out):
    errors = check.run(out, None, ALLOWLIST, bootstrap=True, require_leak_rules=True)
    assert errors == ["leak rules empty (MIRAGE_LEAK_PATTERNS, MIRAGE_LEAK_LITERALS)"]


def test_missing_previous_needs_bootstrap(out, tmp_path):
    assert any("--bootstrap" in e for e in run(out, bootstrap=False))
    empty = tmp_path / "prev"
    (empty / "latest").mkdir(parents=True)
    (empty / "latest/ipv4-7d.txt").write_text("")
    assert any("--bootstrap" in e for e in run(out, empty))


ANONYMIZERS = {"198.51.100.24", "203.0.113.31"}
DOC_IPS = [
    f"{net}.{i}" for net in ("198.51.100", "203.0.113") for i in range(1, 255) if f"{net}.{i}" not in ANONYMIZERS
]


def set_lists(out, prev, old: list[str], new: list[str], rel="latest/ipv4-7d.txt"):
    shutil.copytree(out, prev)
    (prev / rel).write_text("\n".join(old) + "\n")
    (out / rel).write_text("\n".join(new) + "\n")


def delta(out, prev, allow_delta=False):
    return check.check_delta(out, prev, allow_delta, False)


@pytest.mark.parametrize("new", [131, 69])
def test_delta_over_30_percent_trips(out, tmp_path, new):
    set_lists(out, tmp_path / "prev", DOC_IPS[:100], DOC_IPS[:new])
    assert any("size 100 -> " in e for e in delta(out, tmp_path / "prev"))
    assert delta(out, tmp_path / "prev", allow_delta=True) == []


@pytest.mark.parametrize("new", [130, 70])
def test_delta_within_30_percent_passes(out, tmp_path, new):
    set_lists(out, tmp_path / "prev", DOC_IPS[:100], DOC_IPS[:new])
    assert delta(out, tmp_path / "prev") == []


def test_delta_applies_to_urls(out, tmp_path):
    urls = [f"http://payload.example/{i}" for i in range(100)]
    set_lists(out, tmp_path / "prev", urls, urls[:60], rel="latest/urls-7d.txt")
    assert any("urls-7d.txt: size 100 -> 60" in e for e in delta(out, tmp_path / "prev"))


def test_churn_trips(out, tmp_path):
    set_lists(out, tmp_path / "prev", DOC_IPS[:100], DOC_IPS[50:150])
    assert any("50% new and 50% gone" in e for e in delta(out, tmp_path / "prev"))


def test_normal_churn_passes(out, tmp_path):
    set_lists(out, tmp_path / "prev", DOC_IPS[:100], DOC_IPS[20:120])
    assert delta(out, tmp_path / "prev") == []


def set_gap(out, prev, days):
    feed = json.loads((prev / "feed.json").read_text())
    feed["day"] = f"2026-10-{23 - days:02d}"
    (prev / "feed.json").write_text(json.dumps(feed))


@pytest.mark.parametrize(("days", "new", "ok"), [(1, 69, False), (2, 50, True), (3, 31, True), (9, 5, False)])
def test_size_limit_scales_with_the_gap(out, tmp_path, days, new, ok):
    set_lists(out, tmp_path / "prev", DOC_IPS[:100], DOC_IPS[:new])
    set_gap(out, tmp_path / "prev", days)
    assert (delta(out, tmp_path / "prev") == []) is ok


@pytest.mark.parametrize(("days", "shift", "ok"), [(1, 50, False), (3, 60, True), (7, 85, True), (30, 100, False)])
def test_churn_limit_scales_with_the_gap(out, tmp_path, days, shift, ok):
    set_lists(out, tmp_path / "prev", DOC_IPS[:100], DOC_IPS[shift : shift + 100])
    set_gap(out, tmp_path / "prev", days)
    assert (delta(out, tmp_path / "prev") == []) is ok


def test_concentration():
    spread = [(f"{11 + i // 250}.{i % 250}.0.1", str(64500 + i % 20)) for i in range(300)]
    assert check.check_concentration(spread) == []
    one_asn = [(ip, "64500") for ip, _ in spread]
    assert any("AS64500 holds 100%" in e for e in check.check_concentration(one_asn))
    one_block = [(f"203.0.{i // 250}.{i % 250 + 1}", asn) for i, (_, asn) in enumerate(spread)]
    assert any("203.0.0.0/16 holds 100%" in e for e in check.check_concentration(one_block))
    assert check.check_concentration(one_asn[:199]) == []
    half = [(f"203.{i % 200}.{i // 200}.1", "64500" if i < 120 else str(64600 + i)) for i in range(400)]
    assert any("AS64500 holds 30%" in e for e in check.check_concentration(half))
    assert check.check_concentration(half, prev_rows=half[:380]) == []
    assert any("AS64500" in e for e in check.check_concentration(half, prev_rows=half[120:]))


def set_day(root, day):
    feed = json.loads((root / "feed.json").read_text())
    feed["day"] = f"2026-10-{day:02d}"
    (root / "feed.json").write_text(json.dumps(feed))


def three_days(out, tmp_path, old, mid, new, rel="latest/ipv4-7d.txt", write=None):
    """Published build on 10-21, the backend's 10-22 snapshot and today's 10-23 build."""
    prev, middle = tmp_path / "prev", tmp_path / "mid"
    for root, day in ((prev, 21), (middle, 22)):
        shutil.copytree(out, root)
        set_day(root, day)
    for root, values in ((prev, old), (middle, mid), (out, new)):
        if write:
            write(root, values)
        else:
            (root / rel).write_text("\n".join(values) + "\n")
    return prev, middle


URLS = [f"http://payload.example/{i}" for i in range(200)]


def test_sustained_shift_is_accepted(out, tmp_path):
    prev, mid = three_days(out, tmp_path, DOC_IPS[:100], DOC_IPS[:195], DOC_IPS[:200])
    assert list(check.sustained(out, prev, mid)) == ["size latest/ipv4-7d.txt"]


@pytest.mark.parametrize("mid", [100, 140])
def test_one_day_spike_is_refused(out, tmp_path, mid):
    prev, middle = three_days(out, tmp_path, DOC_IPS[:100], DOC_IPS[:mid], DOC_IPS[:200])
    assert check.sustained(out, prev, middle) == {}


def test_missing_or_stale_previous_day_is_refused(out, tmp_path):
    prev, mid = three_days(out, tmp_path, DOC_IPS[:100], DOC_IPS[:195], DOC_IPS[:200])
    assert check.sustained(out, prev, tmp_path / "absent") == {}
    assert check.sustained(out, None, mid) == {}
    set_day(mid, 21)
    assert check.sustained(out, prev, mid) == {}


def test_sustained_concentration_is_accepted(out, tmp_path):
    def rows(share):
        return [(f"{11 + i // 250}.{i % 250}.0.1", "64500" if i < share * 4 else str(64600 + i)) for i in range(400)]

    def write(root, r):
        (root / check.IP_CSVS[0]).write_text("ip,asn\n" + "".join(f"{ip},{asn}\n" for ip, asn in r))

    prev, mid = three_days(out, tmp_path, rows(5), rows(38), rows(40), write=write)
    assert list(check.sustained(out, prev, mid)) == ["asn 64500"]
    _, spike = three_days(out, tmp_path / "spike", rows(5), rows(5), rows(40), write=write)
    assert check.sustained(out, prev, spike) == {}
    # Out within limits of mid, but mid itself had not crossed the limit yet: not two days of the same shift.
    prev, ramp = three_days(out, tmp_path / "ramp", rows(5), rows(22), rows(30), write=write)
    assert check.check_concentration(check._ip_asn_rows(out), check._ip_asn_rows(prev))
    assert check.sustained(out, prev, ramp) == {}


def test_check_cli_overrides_a_sustained_shift(out, tmp_path, capsys):
    prev, mid = three_days(out, tmp_path, URLS[:100], URLS[:195], URLS[:200], rel="latest/urls-7d.txt")
    args = ["check", str(out), "--previous", str(prev), "--allowlist", str(ALLOWLIST)]
    assert main(args) == 1
    assert main([*args, "--confirm-with", str(mid)]) == 0
    assert "::warning::anomaly gate overridden" in capsys.readouterr().out
    assert main([*args, "--confirm-with", str(prev)]) == 1


@pytest.mark.parametrize(
    ("rel", "line"),
    [
        ("latest/ipv4-top1k.txt", "198.51.100.24"),
        ("latest/ipv6-7d.txt", "2001:db8:3:32::/64"),
        ("latest/suricata/mirage-iprep.list", "203.0.113.31,1,100"),
        ("latest/suricata/datasets/ips.lst", "203.0.113.31"),
        ("latest/ipset/mirage.ipset", "add mirage4-tmp 198.51.100.24"),
        ("latest/nft/mirage.nft", "add element inet mirage_feed bad4 { 198.51.100.24 }"),
        ("latest/mikrotik/mirage-7d.rsc", ":do { add list=mirage-feed address=198.51.100.24 timeout=7d }"),
        ("latest/crowdsec/mirage-7d.csv", "168h,Ip,198.51.100.24,mirage-feed"),
        ("latest/zeek/mirage.intel", "198.51.100.24\tIntel::ADDR\tmirage-feed\tx\ty"),
    ],
)
def test_anonymizer_in_blocklist_trips(out, rel, line):
    append(out / rel, line)
    assert any(e.startswith(f"{rel}: anonymizer ") for e in run(out))


def test_change_lists_match_the_7d_list(out):
    append(out / "latest/ipv4-removed-1d.txt", "10.0.0.1")
    assert run(out) == []
    week = text_lines(out, "latest/ipv4-7d.txt")
    append(out / "latest/ipv4-removed-1d.txt", week[0])
    append(out / "latest/ipv4-added-1d.txt", "198.51.100.250")
    errors = run(out)
    assert f"latest/ipv4-removed-1d.txt: {week[0]} is still in ipv4-7d.txt" in errors
    assert "latest/ipv4-added-1d.txt: 198.51.100.250 is not in ipv4-7d.txt" in errors


def test_anonymizer_with_ids_in_misp_trips(out):
    event = next(p for p in (out / "misp").glob("*-*.json"))
    body = json.loads(event.read_text())
    attr = next(a for a in body["Event"]["Attribute"] if a["value"] == "198.51.100.24")
    attr["to_ids"] = True
    event.write_text(json.dumps(body))
    assert any(e.startswith(f"misp/{event.name}: anonymizer 198.51.100.24") for e in run(out))


def test_anonymizer_as_malicious_stix_indicator_trips(out):
    path = out / "latest/stix/mirage.json"
    bundle = json.loads(path.read_text())
    for o in bundle["objects"]:
        if o.get("pattern") == "[ipv4-addr:value = '198.51.100.24']":
            o["indicator_types"] = ["malicious-activity"]
    path.write_text(json.dumps(bundle))
    assert "latest/stix/mirage.json: anonymizer 198.51.100.24 is in a block list" in run(out)


def test_schema_violation_trips(out):
    path = out / "latest/records-7d.ndjson.gz"
    bad = {
        "type": "ipv4",
        "value": "203.0.113.9",
        "first_seen": "2026-10-01T00:00:00Z",
        "last_seen": "2026-10-02T00:00:00Z",
    }
    path.write_bytes(gzip.compress(gzip.decompress(path.read_bytes()) + json.dumps(bad).encode() + b"\n"))
    assert any("records-7d.ndjson.gz line" in e for e in run(out))


def test_stix_structure_trips(out):
    path = out / "latest/stix/mirage.json"
    bundle = json.loads(path.read_text())
    bundle["objects"].append(dict(bundle["objects"][-1]))
    bundle["objects"] = [o for o in bundle["objects"] if o["type"] != "marking-definition"]
    path.write_text(json.dumps(bundle))
    errors = run(out)
    assert any("duplicate id" in e for e in errors)
    assert any("TLP:CLEAR marking-definition missing" in e for e in errors)


def test_missing_output_trips(out):
    (out / "latest/nft/mirage.nft").unlink()
    assert run(out) == ["missing output latest/nft/mirage.nft"]
