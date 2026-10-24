import hashlib
import json
from pathlib import Path

from .common import Artifact, Snapshot, anonymizer, dumps, network, parse_ts, uid
from .netlist import DEFAULT_ALLOWLIST, Allowlist

KEEP_EVENTS = 8
MANIFEST_KEYS = ("info", "date", "analysis", "threat_level_id", "timestamp", "Orgc", "Tag")
ORGC = {"name": "OffSeq", "uuid": uid("misp-org", "offseq")}
TAGS = [{"name": "tlp:clear", "colour": "#ffffff"}]
CONSUMERS = ("misp",)
# (category, to_ids) per MISP attribute type
TYPES = {
    "ip-src": ("Network activity", True),
    "url": ("Network activity", True),
    "domain": ("Network activity", True),
    "sha256": ("Payload delivery", True),
    "user-agent": ("Network activity", False),
    "vulnerability": ("External analysis", False),
    "hassh-md5": ("Network activity", False),
}


def _attributes(s: Snapshot) -> list[tuple[str, str, str, bool]]:
    # VPN and Tor exits are shared egress: context for analysts, never an IDS or block signal.
    ips = [
        ("ip-src", r["ip"], f"confidence={r['confidence']} tags={';'.join(r.get('tags', []))}", not anonymizer(r))
        for r in s.ips_in("7d")
    ]
    attrs = [("url", r["url"], r["kind"]) for r in s.lists["urls"]]
    attrs += [("domain", r["domain"], "") for r in s.lists["domains"]]
    attrs += [("sha256", r["sha256"], "") for r in s.lists["hashes"]]
    attrs += [("user-agent", r["value"], "") for r in s.lists["user_agents"]]
    attrs += [("vulnerability", r["cve"], "CISA KEV" if r.get("kev") else "") for r in s.lists["cves"]]
    attrs += [("hassh-md5", r["value"], r.get("tool") or "") for r in s.lists["fingerprints"] if r["type"] == "hassh"]
    return sorted(set(ips) | {(*a, TYPES[a[0]][1]) for a in attrs})


def event(s: Snapshot) -> tuple[str, dict]:
    event_uuid = uid("misp-event", s.day)
    stamp = str(int(parse_ts(s.generated).timestamp()))
    attributes = [
        {
            "uuid": uid("misp-attr", s.day, kind, value),
            "type": kind,
            "category": TYPES[kind][0],
            "value": value,
            "to_ids": to_ids,
            "comment": comment,
            "timestamp": stamp,
            "distribution": "5",
        }
        for kind, value, comment, to_ids in _attributes(s)
    ]
    header = {
        "info": f"OffSeq Mirage community feed {s.day}",
        "date": s.day,
        "analysis": "2",
        "threat_level_id": "3",
        "timestamp": stamp,
        "publish_timestamp": stamp,
        "Orgc": ORGC,
        "Tag": TAGS,
    }
    body = {"Event": {**header, "uuid": event_uuid, "published": True, "distribution": "3", "Attribute": attributes}}
    return event_uuid, body


def _carried(prev: Path | None, s: Snapshot, allow: Allowlist) -> dict[str, dict]:
    """Earlier events; IPs no longer listed, now allowlisted or now anonymizers are marked deleted."""
    manifest = prev / "misp" / "manifest.json" if prev else None
    if not manifest or not manifest.is_file():
        return {}
    stamp = str(int(parse_ts(s.generated).timestamp()))
    # An IDS attribute needs a block-listed address; an anonymizer context attribute only a listed one.
    live = {True: {r["ip"] for r in s.blockable("30d")}, False: {r["ip"] for r in s.ips_in("30d")}}
    kept = {}
    entries = json.loads(manifest.read_text(encoding="utf-8"))
    for event_uuid, meta in sorted(entries.items(), key=lambda kv: kv[1]["date"], reverse=True):
        path = manifest.parent / f"{event_uuid}.json"
        if meta["date"] == s.day or not path.is_file() or len(kept) == KEEP_EVENTS - 1:
            continue
        body = json.loads(path.read_text(encoding="utf-8"))
        ev = body["Event"]
        pruned = False
        for a in ev.get("Attribute", []):
            if a.get("deleted") or a["type"] != "ip-src":
                continue
            if a["value"] not in live[bool(a.get("to_ids"))] or allow.hit(network(a["value"])):
                # MISP only re-pulls an event whose timestamp moved, and only drops attributes sent as deleted.
                a.update(deleted=True, to_ids=False, timestamp=stamp)
                pruned = True
        if pruned:
            ev["timestamp"] = ev["publish_timestamp"] = stamp
        kept[event_uuid] = body
    return kept


def render(s: Snapshot, prev: Path | None = None, allow: Allowlist | None = None) -> list[Artifact]:
    today_uuid, today = event(s)
    events = _carried(prev, s, allow or Allowlist(DEFAULT_ALLOWLIST))
    events[today_uuid] = today
    manifest, hashes, out = {}, [], []
    for event_uuid, body in sorted(events.items()):
        ev = body["Event"]
        manifest[event_uuid] = {k: ev[k] for k in MANIFEST_KEYS}
        attrs = [a for a in ev.get("Attribute", []) if not a.get("deleted")]
        hashes += [(hashlib.md5(a["value"].encode(), usedforsecurity=False).hexdigest(), event_uuid) for a in attrs]
        out.append(Artifact(f"misp/{event_uuid}.json", dumps(body), "misp-event", len(attrs), "7d", CONSUMERS))
    hashes_csv = "".join(f"{h},{e}\n" for h, e in sorted(hashes)).encode()
    out.append(Artifact("misp/manifest.json", dumps(manifest), "misp-manifest", len(manifest), None, CONSUMERS))
    out.append(Artifact("misp/hashes.csv", hashes_csv, "misp-hashes", len(hashes), None, CONSUMERS))
    return out
