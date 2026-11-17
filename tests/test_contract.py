"""Paths and columns that tools outside this repo fetch and parse.

A failure here means a published consumer breaks: announce the change in CHANGELOG.md and to the consumer first.
"""

import csv
import ipaddress
import json
import re
import tarfile

import pytest

CSV_COLUMNS = [
    (
        "CIRCL MirageSight (vulnerability.circl.lu sightings)",
        "latest/cves-7d.csv",
        {"cve", "name", "kev", "attempts", "sources", "first_seen", "last_seen"},
    ),
    (
        "Yeti OffSeqMirage feed",
        "latest/attackers-ipv4-7d.csv",
        {
            "ip",
            "asn",
            "as_org",
            "country",
            "first_seen",
            "last_seen",
            "services",
            "tags",
            "cves",
            "attack",
            "confidence",
        },
    ),
]

ISO_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")


@pytest.mark.parametrize(("consumer", "path", "columns"), CSV_COLUMNS, ids=[c[1] for c in CSV_COLUMNS])
def test_csv_columns(out, consumer, path, columns):
    with (out / path).open(newline="") as fh:
        rows = list(csv.DictReader(fh))
    missing = columns - set(rows[0])
    assert not missing, f"{consumer} reads {path} columns {sorted(missing)}"
    for row in rows:
        for field in ("first_seen", "last_seen"):
            assert ISO_UTC.fullmatch(row[field]), f"{consumer} parses {path} {field} as ISO 8601 UTC: {row[field]!r}"


@pytest.mark.parametrize(
    ("consumer", "path"),
    [
        ("FireHOL, crowdsec-blocklist-import, Bert-JanP feed list", "latest/ipv4-7d.txt"),
        ("Yeti OffSeqMirage feed, Bert-JanP feed list", "latest/urls-7d.txt"),
    ],
)
def test_plain_lists(out, consumer, path):
    lines = (out / path).read_text().splitlines()
    assert lines, f"{consumer} fetches {path}"
    for line in lines:
        if path.endswith("ipv4-7d.txt"):
            assert ipaddress.ip_address(line).version == 4, f"{consumer} reads one IPv4 per line in {path}: {line!r}"
        else:
            assert line.startswith(("http://", "https://")), f"{consumer} reads one URL per line in {path}: {line!r}"


def test_zeek_intel(out):
    header = (out / "latest/zeek/mirage.intel").read_text().splitlines()[0]
    assert header.split("\t")[:3] == ["#fields", "indicator", "indicator_type"], (
        "zeek-offseq-mirage loads latest/zeek/mirage.intel through the Intel framework"
    )


def test_suricata_update_bundle(out):
    with tarfile.open(out / "latest/suricata/mirage.tar.gz") as tar:
        names = set(tar.getnames())
        rules = tar.extractfile("rules/mirage.rules").read().decode()
    assert {"rules/mirage.rules", "rules/datasets/ips.lst"} <= names, (
        "suricata-update users install latest/suricata/mirage.tar.gz"
    )
    sids = {int(s) for s in re.findall(r"sid:(\d+);", rules)}
    assert sids and sids <= set(range(3510000, 3520000)), (
        f"suricata-update bundle SIDs must stay in the requested 3510000-3519999 range: {sorted(sids)}"
    )


def test_stix_bundle(out):
    bundle = json.loads((out / "latest/stix/mirage.json").read_text())
    assert bundle["type"] == "bundle", "the OpenCTI connector imports latest/stix/mirage.json as a STIX bundle"
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert indicators and all(o.get("spec_version") == "2.1" for o in indicators), (
        "the OpenCTI connector expects STIX 2.1 indicators in latest/stix/mirage.json"
    )


def test_misp_manifest(out):
    manifest = json.loads((out / "misp/manifest.json").read_text())
    for event in (out / "misp").glob("*.json"):
        if event.name != "manifest.json":
            assert event.stem in manifest, f"MISP instances sync misp/manifest.json, which must list {event.name}"
