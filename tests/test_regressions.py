import base64
import copy
import csv
import hashlib
import http.client
import json
import shutil
import zlib

import pytest

from generator import build, check, fetch, firewall, nsm
from generator.common import Snapshot, ip_key, parse_ts
from generator.netlist import Allowlist

from .conftest import ALLOWLIST, SNAPSHOT

FIX = json.loads(SNAPSHOT.read_text())
NEXT = {"day": "2026-10-24", "generated": "2026-10-25T03:05:00Z"}
V4_7D = "latest/ipv4-7d.txt"


def snap(**change) -> dict:
    raw = copy.deepcopy(FIX)
    raw.update(change)
    return raw


def run_build(tmp_path, raw, prev=None, name="out"):
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps(raw))
    build.build(path, tmp_path / name, prev, ALLOWLIST)
    return tmp_path / name


def lines(out, rel) -> list[str]:
    return (out / rel).read_text().splitlines()


def plain_v4(raw) -> list[str]:
    return [
        r["ip"]
        for r in raw["ips"]
        if r["window"] != "30d" and ":" not in r["ip"] and not {"vpn-exit", "tor-exit"} & set(r["tags"])
    ]


@pytest.mark.parametrize(
    ("pattern", "text"),
    [(r"zz\Dmarker", "zz_marker"), (r"node\S+\.lan", "node-7.lan"), (r"leak-token\n\Z", "leak-token")],
)
def test_leak_pattern_source_is_not_normalised(out, pattern, text):
    (out / "latest/urls-7d.txt").write_text(text + "\n")
    assert check.check_leaks(out, [pattern], [], True) == ["leak in latest/urls-7d.txt"]


def test_encoded_dot_in_leak_pattern_is_not_a_wildcard(out):
    (out / "latest/urls-7d.txt").write_text("zzXmarker\n")
    assert check.check_leaks(out, ["zz%2emarker"], [], True) == []


def test_removed_is_the_complement_of_added(tmp_path):
    ip = plain_v4(FIX)[0]
    out1 = run_build(tmp_path, snap(), name="d1")
    raw = snap(**NEXT)
    next(r for r in raw["ips"] if r["ip"] == ip)["tags"] = ["vpn-exit"]
    raw["ips"] = [r for r in raw["ips"] if r["ip"] != plain_v4(FIX)[1]]
    out2 = run_build(tmp_path, raw, out1, "d2")
    old, new = set(lines(out1, V4_7D)), set(lines(out2, V4_7D))
    added, removed = set(lines(out2, "latest/ipv4-added-1d.txt")), set(lines(out2, "latest/ipv4-removed-1d.txt"))
    assert (old | added) - removed == new
    assert {ip, plain_v4(FIX)[1]} <= removed
    assert check.run(out2, out1, ALLOWLIST) == []


def test_same_day_rebuild_keeps_the_change_lists(tmp_path):
    out1 = run_build(tmp_path, snap(), name="d1")
    raw = snap(**NEXT)
    gone = plain_v4(FIX)[:2]
    raw["ips"] = [r for r in raw["ips"] if r["ip"] not in gone]
    out2 = run_build(tmp_path, raw, out1, "d2")
    assert lines(out2, "latest/ipv4-removed-1d.txt") == sorted(gone)

    rerun = run_build(tmp_path, {**raw, "generated": "2026-10-25T05:00:00Z"}, out2, "d2b")
    for rel in ("latest/ipv4-added-1d.txt", "latest/ipv4-removed-1d.txt"):
        assert lines(rerun, rel) == lines(out2, rel)
    assert json.loads((rerun / "history.json").read_text())[-1]["removed"] == 2

    raw["ips"] = [r for r in raw["ips"] if r["ip"] != plain_v4(FIX)[2]]
    changed = run_build(tmp_path, {**raw, "generated": "2026-10-25T06:00:00Z"}, rerun, "d2c")
    old, new = set(lines(out1, V4_7D)), set(lines(changed, V4_7D))
    assert set(lines(changed, "latest/ipv4-removed-1d.txt")) == old - new == {*gone, plain_v4(FIX)[2]}
    assert set(lines(changed, "latest/ipv4-added-1d.txt")) == new - old


def test_rollback_is_gated(tmp_path):
    out1 = run_build(tmp_path, snap(), name="r1")
    out2 = run_build(tmp_path, snap(day="2026-10-22", generated="2026-10-23T03:05:00Z"), out1, "r2")
    errors = check.run(out2, out1, ALLOWLIST)
    assert any("older than the previous build" in e for e in errors)
    assert check.run(out2, out1, ALLOWLIST, allow_rollback=True, allow_delta=True) == []


def test_same_snapshot_rerun_is_identical_and_passes(tmp_path):
    out1 = run_build(tmp_path, snap(), name="s1")
    out2 = run_build(tmp_path, snap(), out1, "s2")
    assert check.check_rollback(out2, out1) == []
    for rel in ("SHA256SUMS", "history.json", "latest/ipv4-added-1d.txt", "latest/ipv4-removed-1d.txt"):
        assert (out2 / rel).read_bytes() == (out1 / rel).read_bytes()


def test_empty_previous_7d_list_is_a_real_previous(tmp_path, out):
    prev = tmp_path / "prev"
    shutil.copytree(out, prev)
    (prev / V4_7D).write_text("")
    assert not any("--bootstrap" in e for e in check.check_delta(out, prev, True, False))
    shutil.rmtree(prev / "latest")
    (prev / "feed.json").unlink()
    assert any("--bootstrap" in e for e in check.check_delta(out, prev, True, False))


def test_misp_pruned_attribute_loads_as_deleted(tmp_path):
    pymisp = pytest.importorskip("pymisp")
    out1 = run_build(tmp_path, snap(), name="m1")
    ip = plain_v4(FIX)[0]
    out2 = run_build(tmp_path, snap(**NEXT, ips=[r for r in FIX["ips"] if r["ip"] != ip]), out1, "m2")
    uuid = next(iter(json.loads((out1 / "misp/manifest.json").read_text())))
    event = pymisp.MISPEvent()
    event.load_file(out2 / f"misp/{uuid}.json")
    assert [a.deleted for a in event.attributes if a.value == ip] == [True]


def test_expiry_is_after_the_build(tmp_path):
    raw = snap()
    raw["ips"][0].update(last_seen="2026-10-16T00:00:00Z", confidence=100)
    s = Snapshot(raw)
    assert all(r[2] > s.generated for r in firewall.defender(s.ranked_v4(500), s.generated))
    out = run_build(tmp_path, raw)
    assert check.run(out, None, ALLOWLIST, bootstrap=True) == []
    bundle = json.loads((out / "latest/stix/mirage.json").read_text())
    assert all(o["valid_until"] > "2026-10-25" for o in bundle["objects"] if o["type"] == "indicator")


def test_past_expiry_trips(out):
    rel = "latest/defender/defender-top500.csv"
    with (out / rel).open(newline="") as fh:
        rows = list(csv.reader(fh))
    rows[1][2] = "2026-10-20T00:00:00.0Z"
    with (out / rel).open("w", newline="") as fh:
        csv.writer(fh, lineterminator="\r\n").writerows(rows)
    path = out / "latest/stix/mirage.json"
    bundle = json.loads(path.read_text())
    ind = next(o for o in bundle["objects"] if o["type"] == "indicator")
    ind["valid_until"] = "2026-10-20T00:00:00.000Z"
    path.write_text(json.dumps(bundle))
    errors = check.check_expiry(out)
    assert any(e.startswith(f"{rel}: {rows[1][1]} expires") for e in errors)
    assert f"stix: {ind['id']} expires 2026-10-20T00:00:00.000Z" in errors


def test_stix_created_is_stable_and_modified_is_the_build(tmp_path):
    out1 = run_build(tmp_path, snap(), name="s1")
    raw = snap(**NEXT)
    rec = next(r for r in raw["ips"] if r["window"] == "7d")
    rec["first_seen"], rec["last_seen"] = "2026-10-20T00:00:00Z", "2026-10-21T00:00:00Z"
    out2 = run_build(tmp_path, raw, out1, "s2")

    def indicator(out):
        objects = json.loads((out / "latest/stix/mirage.json").read_text())["objects"]
        return next(o for o in objects if o.get("pattern") == f"[ipv4-addr:value = '{rec['ip']}']")

    first, second = indicator(out1), indicator(out2)
    assert second["id"] == first["id"] and second["created"] == first["created"]
    assert second["modified"] == "2026-10-25T03:05:00.000Z" and second["valid_from"] == "2026-10-20T00:00:00.000Z"


@pytest.mark.parametrize(
    ("kind", "field"),
    [("urls", "sightings"), ("hashes", "first_seen"), ("domains", "sources"), ("fingerprints", "sources"),
     ("passwords", "sources"), ("cves", "sources")],
)  # fmt: skip
def test_malformed_record_is_dropped_not_fatal(tmp_path, kind, field):
    raw = snap()
    del raw[kind][0][field]
    out = run_build(tmp_path, raw)
    base = Snapshot(snap()).dropped
    assert Snapshot(raw).dropped == {**base, kind: base.get(kind, 0) + 1}
    assert check.run(out, None, ALLOWLIST, bootstrap=True) == []


@pytest.mark.parametrize("value", ["1", 1.5, -1, True])
def test_bad_count_is_dropped(value):
    raw = snap()
    raw["urls"][0]["sources"] = value
    assert raw["urls"][0]["url"] not in {u["url"] for u in Snapshot(raw).lists["urls"]}


def test_string_tags_drop_the_record():
    raw = snap()
    raw["ips"][0]["tags"] = "vpn-exit"
    assert raw["ips"][0]["ip"] not in {r["ip"] for r in Snapshot(raw).lists["ips"]}


def test_ipset_maxelem_is_fixed(out):
    creates = [line for line in lines(out, "latest/ipset/mirage.ipset") if line.startswith("create ")]
    assert creates and all(line.split()[-2:] == ["1048576", "-exist"] for line in creates)


def test_stats_describe_the_published_files(out):
    pub = json.loads((out / "stats.json").read_text())["published"]
    assert pub["ips"] == len(lines(out, V4_7D)) + len(lines(out, "latest/ipv6-7d.txt")) == 62
    assert pub["ips_30d"] == len(lines(out, "latest/ipv4-30d.txt")) + len(lines(out, "latest/ipv6-7d.txt"))
    assert pub["active_24h"] == len(lines(out, "latest/ipv4-1d.txt")) == 13
    assert pub["scanners"] == sum(len(lines(out, f"latest/known-scanners-ipv{v}.txt")) for v in (4, 6))
    with (out / "latest/attackers-7d.csv").open(newline="") as fh:
        rows = [r for r in csv.DictReader(fh) if not {"vpn-exit", "tor-exit"} & set(r["tags"].split(";"))]
    assert pub["asns"] == len({r["asn"] for r in rows if r["asn"]})
    assert pub["countries"] == len({r["country"] for r in rows if r["country"]})


def test_lookup_shards_cover_the_lists(out):
    shard = json.loads((out / "latest/lookup/v4/198.json").read_text())
    assert shard["198.51.100.24"]["lists"] == ["anonymizers-7d.txt"]
    assert "vpn-exit" in shard["198.51.100.24"]["record"]["tags"]
    assert "window" not in shard["198.51.100.24"]["record"]
    v6 = json.loads((out / "latest/lookup/v6/2001.json").read_text())
    assert all(k.startswith("2001:") for k in v6)
    assert check.check_lookup(out) == []
    (out / "latest/ipv4-7d.txt").write_text((out / "latest/ipv4-7d.txt").read_text() + "198.51.100.250\n")
    del shard["198.51.100.24"]
    shard["198.51.100.9"]["lists"] = ["ipv4-7d.txt"]
    (out / "latest/lookup/v4/198.json").write_text(json.dumps(shard))
    errors = check.check_lookup(out)
    assert "latest/lookup/: 198.51.100.250 missing" in errors
    assert "latest/lookup/: 198.51.100.24 missing" in errors
    assert any(e.startswith("latest/lookup/: 198.51.100.9 lists ['ipv4-7d.txt']") for e in errors)


def test_fetch_retries_incomplete_read(monkeypatch, tmp_path):
    monkeypatch.setenv(fetch.TOKEN_ENV, "t0ken")
    answers = [http.client.IncompleteRead(b"{"), SNAPSHOT.read_bytes()]

    def get(url, token):
        item = answers.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    monkeypatch.setattr(fetch, "_get", get)
    assert fetch.fetch("https://x/api", tmp_path / "s.json", "2026-10-23", sleep=lambda _: None).day == "2026-10-23"


def test_vpn_client_uas_stay_out_of_ids_rules():
    raw = snap()
    raw["user_agents"].append({"value": "AnyConnect Windows 5.1.7.80", "sources": 3})
    s = Snapshot(raw)
    assert "AnyConnect Windows 5.1.7.80" in {r["value"] for r in s.lists["user_agents"]}
    rendered = b"".join(a.data for a in nsm.render(s))
    assert b"AnyConnect" not in rendered and base64.b64encode(b"AnyConnect Windows 5.1.7.80") not in rendered


def test_hash_rule_needs_hashes():
    with_hashes = Snapshot(snap())
    without = Snapshot(snap(hashes=[]))
    rules = {s: next(a for a in nsm.render(s) if a.path.endswith("mirage.rules")) for s in (with_hashes, without)}
    assert b"sid:1900004" in rules[with_hashes].data and rules[with_hashes].count == 4
    assert b"sid:1900004" not in rules[without].data and rules[without].count == 3


@pytest.mark.parametrize("value", [["x"], {"a": 1}, 5])
def test_non_string_labels_are_left_empty(tmp_path, value):
    raw = snap()
    raw["fingerprints"][0]["tool"] = value
    raw["cves"][0]["name"] = value
    s = Snapshot(raw)
    assert s.lists["fingerprints"][0]["tool"] is None and s.lists["cves"][0]["name"] is None
    run_build(tmp_path, raw)


def test_fetch_retries_corrupt_gzip(monkeypatch, tmp_path):
    monkeypatch.setenv(fetch.TOKEN_ENV, "t0ken")
    answers = [zlib.error("invalid stored block lengths"), SNAPSHOT.read_bytes()]

    def get(url, token):
        item = answers.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    monkeypatch.setattr(fetch, "_get", get)
    assert fetch.fetch("https://x/api", tmp_path / "s.json", "2026-10-23", sleep=lambda _: None).day == "2026-10-23"


def _vpn_botnet(raw, cves=()):
    rec = next(r for r in raw["ips"] if r["ip"] == "198.51.100.9")
    rec.update(tags=["vpn-bruteforce", "web-exploit"], attack=["T1110", "T1190"], cves=list(cves), confidence=100)
    return raw


def test_vpn_bruteforce_only_stays_out_of_high_confidence_lists(tmp_path):
    raw = _vpn_botnet(snap())
    out = run_build(tmp_path, raw)
    assert "198.51.100.9" in lines(out, V4_7D)
    assert "198.51.100.9" not in lines(out, "latest/ipv4-top1k.txt")
    assert "198.51.100.9" not in (out / "latest/defender/defender-top500.csv").read_text()
    assert "198.51.100.9,1,80" in lines(out, "latest/suricata/mirage-iprep.list")
    with_cve = Snapshot(_vpn_botnet(snap(), cves=["CVE-2018-13379"]))
    assert "198.51.100.9" in {r["ip"] for r in with_cve.ranked_v4(1000)}


def test_allowlisted_scanners_are_dropped():
    raw = snap()
    raw["scanners"].append({"ip": "8.8.8.8", "name": "crawler"})
    s = Snapshot(raw, Allowlist(ALLOWLIST))
    assert "8.8.8.8" not in {r["ip"] for r in s.lists["scanners"]}
    assert "8.8.8.8" in {r["ip"] for r in Snapshot(raw).lists["scanners"]}


def test_kev_follows_the_published_cves():
    raw = snap()
    rec = next(r for r in raw["ips"] if r["ip"] == "198.51.100.9")
    rec.update(kev=True, cves=[])
    s = Snapshot(raw)
    kev = {r["ip"]: r["kev"] for r in s.lists["ips"]}
    assert kev["198.51.100.9"] is False and kev["203.0.113.39"] is True


def test_zeek_ips_sort_numerically(out):
    rows = [line.split("\t") for line in lines(out, "latest/zeek/mirage.intel")[1:]]
    ips = [r[0] for r in rows if r[1] in ("Intel::ADDR", "Intel::SUBNET")]
    assert ips == sorted(ips, key=ip_key) != sorted(ips)


def test_carried_misp_events_are_refiltered(tmp_path):
    out1 = run_build(tmp_path, snap(), name="r1")
    uuid = next(iter(json.loads((out1 / "misp/manifest.json").read_text())))
    path = out1 / f"misp/{uuid}.json"
    body = json.loads(path.read_text())
    attr = next(a for a in body["Event"]["Attribute"] if a["type"] == "url")
    body["Event"]["Attribute"].append({**attr, "type": "domain", "value": "dpaste.org", "uuid": "x"})
    path.write_text(json.dumps(body))
    out2 = run_build(tmp_path, snap(**NEXT), out1, "r2")
    ev = json.loads((out2 / f"misp/{uuid}.json").read_text())["Event"]
    stamp = str(int(parse_ts(NEXT["generated"]).timestamp()))
    assert [(a["deleted"], a["to_ids"], a["timestamp"]) for a in ev["Attribute"] if a["value"] == "dpaste.org"] == [
        (True, False, stamp)
    ]
    assert ev["timestamp"] == stamp
    assert hashlib.md5(b"dpaste.org").hexdigest() not in (out2 / "misp/hashes.csv").read_text()
