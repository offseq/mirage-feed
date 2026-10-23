import gzip
import io

from .common import JA4_TYPES, Artifact, Snapshot, csv_bytes, dumps, network

ATTACKER_COLS = (
    "ip",
    "asn",
    "as_org",
    "country",
    "first_seen",
    "last_seen",
    "services",
    "tags",
    "cves",
    "kev",
    "attack",
    "sensors",
    "networks",
    "hits",
    "confidence",
)
CVE_COLS = ("cve", "name", "kev", "attempts", "sources", "first_seen", "last_seen")
# FoxIO ja4plus-mapping.csv layout, extended with observation columns.
FOXIO_COLS = (
    "Application",
    "Library",
    "Device",
    "OS",
    "ja4",
    "ja4s",
    "ja4h",
    "ja4x",
    "ja4t",
    "ja4tscan",
    "Notes",
    "first_seen",
    "last_seen",
    "count",
    "cluster",
)
HASSH_COLS = ("hassh", "type", "tool", "sources", "hits", "first_seen", "last_seen")
IP_FIELDS = (
    "asn",
    "as_org",
    "country",
    "first_seen",
    "last_seen",
    "services",
    "tags",
    "attack",
    "cves",
    "kev",
    "sensors",
    "networks",
    "hits",
    "confidence",
    "window",
)
OBS_FIELDS = ("sightings", "sources", "first_seen", "last_seen")


def records(s: Snapshot) -> list[dict]:
    out = []
    for r in s.ips_in("7d"):
        kind = "ipv4" if network(r["ip"]).version == 4 else "ipv6"
        out.append({"type": kind, "value": r["ip"], **{k: r[k] for k in IP_FIELDS if k in r}})
    for kind, source in (("url", "urls"), ("domain", "domains"), ("sha256", "hashes")):
        for r in sorted(s.lists[source], key=lambda r: r[kind]):
            rec = {"type": kind, "value": r[kind], **{k: r[k] for k in OBS_FIELDS}}
            if kind == "url":
                rec["kind"] = r["kind"]
            out.append(rec)
    return out


def _gzip(data: bytes) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buf, mtime=0, compresslevel=9) as gz:
        gz.write(data)
    return buf.getvalue()


def _fingerprints(s: Snapshot) -> tuple[list[list], list[list]]:
    foxio, hassh = [], []
    for f in sorted(s.lists["fingerprints"], key=lambda f: (f["type"], f["value"])):
        seen = (f.get("first_seen"), f.get("last_seen"))
        if f["type"] in JA4_TYPES:
            row = dict.fromkeys(FOXIO_COLS)
            row.update(
                {
                    f["type"]: f["value"],
                    "Application": f.get("tool"),
                    "first_seen": seen[0],
                    "last_seen": seen[1],
                    "count": f.get("hits"),
                    "cluster": f.get("cluster"),
                    "Notes": f"sources={f['sources']}",
                }
            )
            foxio.append([row[c] for c in FOXIO_COLS])
        else:
            hassh.append([f["value"], f["type"], f.get("tool"), f["sources"], f.get("hits"), *seen])
    return foxio, hassh


def render(s: Snapshot) -> list[Artifact]:
    attackers = [[r.get(c) for c in ATTACKER_COLS] for r in s.ips_in("7d")]
    # The OpenCTI mapper builds an Autonomous-System from every row, and a row without an ASN fails it.
    attackers4 = [[r.get(c) for c in ATTACKER_COLS] for r in s.ips_in("7d", 4) if r.get("asn") is not None]
    cves = [[c.get(k) for k in CVE_COLS] for c in sorted(s.lists["cves"], key=lambda c: c["cve"])]
    foxio, hassh = _fingerprints(s)
    recs = records(s)
    ndjson = b"".join(dumps(r) for r in recs)
    siem = ("splunk", "sentinel", "elastic")
    return [
        Artifact("latest/attackers-7d.csv", csv_bytes(ATTACKER_COLS, attackers), "csv", len(attackers), "7d", siem),
        Artifact(
            "latest/attackers-ipv4-7d.csv",
            csv_bytes(ATTACKER_COLS, attackers4),
            "csv",
            len(attackers4),
            "7d",
            ("opencti",),
        ),
        Artifact("latest/cves-7d.csv", csv_bytes(CVE_COLS, cves), "csv", len(cves), "7d", ("siem", "vuln-mgmt")),
        Artifact(
            "latest/fingerprints.csv",
            csv_bytes(FOXIO_COLS, foxio),
            "csv",
            len(foxio),
            None,
            ("ja4plus", "zeek", "suricata"),
        ),
        Artifact("latest/hassh.csv", csv_bytes(HASSH_COLS, hassh), "csv", len(hassh), None, ("zeek", "siem")),
        Artifact(
            "latest/records-7d.ndjson.gz", _gzip(ndjson), "ndjson+gzip", len(recs), "7d", ("elastic", "splunk", "jq")
        ),
    ]
