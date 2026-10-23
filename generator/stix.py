from .common import Artifact, Snapshot, anonymizer, dumps, expiry, network, parse_ts, uid

TLP_CLEAR_ID = "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
TLP_EXTENSION = "extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d"
TLP_CLEAR = {
    "type": "marking-definition",
    "spec_version": "2.1",
    "id": TLP_CLEAR_ID,
    "created": "2022-10-01T00:00:00.000Z",
    "name": "TLP:CLEAR",
    "extensions": {TLP_EXTENSION: {"extension_type": "property-extension", "tlp_2_0": "clear"}},
}
EPOCH = "2026-10-01T00:00:00.000Z"
IDENTITY_ID = f"identity--{uid('identity', 'offseq')}"
IDENTITY = {
    "type": "identity",
    "spec_version": "2.1",
    "id": IDENTITY_ID,
    "created": EPOCH,
    "modified": EPOCH,
    "name": "OffSeq",
    "identity_class": "organization",
    "contact_information": "abuse@offseq.com",
    "object_marking_refs": [TLP_CLEAR_ID],
}


def ts(value: str) -> str:
    return parse_ts(value).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _sdo(kind: str, key: str, created: str, modified: str, **props) -> dict:
    return {
        "type": kind,
        "spec_version": "2.1",
        "id": f"{kind}--{uid(kind, key)}",
        "created": created,
        "modified": modified,
        "created_by_ref": IDENTITY_ID,
        "object_marking_refs": [TLP_CLEAR_ID],
        **props,
    }


def _indicator(name: str, pattern: str, rec: dict, kind: str = "malicious-activity", **props) -> dict:
    return _sdo(
        "indicator",
        pattern,
        ts(rec["first_seen"]),
        ts(rec["last_seen"]),
        name=name,
        pattern=pattern,
        pattern_type="stix",
        valid_from=ts(rec["first_seen"]),
        valid_until=expiry(rec["last_seen"]).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        indicator_types=[kind],
        **props,
    )


def _relationship(rel: str, src: str, dst: str) -> dict:
    return _sdo(
        "relationship", f"{rel}:{src}:{dst}", EPOCH, EPOCH, relationship_type=rel, source_ref=src, target_ref=dst
    )


def _attack_pattern(technique: str, names: dict[str, str]) -> dict:
    url = "https://attack.mitre.org/techniques/" + technique.replace(".", "/") + "/"
    return _sdo(
        "attack-pattern",
        technique,
        EPOCH,
        EPOCH,
        name=names.get(technique, technique),
        external_references=[{"source_name": "mitre-attack", "external_id": technique, "url": url}],
    )


def _vulnerability(cve: str, kev: bool) -> dict:
    refs = [{"source_name": "cve", "external_id": cve}]
    return _sdo(
        "vulnerability",
        cve,
        EPOCH,
        EPOCH,
        name=cve,
        external_references=refs,
        **({"labels": ["cisa-kev"]} if kev else {}),
    )


def bundle(s: Snapshot) -> dict:
    names = {a["technique"]: a["name"] for a in s.stats.get("attack", []) if a.get("name")}
    kev = {c["cve"]: bool(c.get("kev")) for c in s.lists["cves"]}
    objects = {o["id"]: o for o in (TLP_CLEAR, IDENTITY)}

    def add(obj: dict) -> str:
        objects.setdefault(obj["id"], obj)
        return obj["id"]

    for rec in s.ips_in("7d"):
        family = "ipv4-addr" if network(rec["ip"]).version == 4 else "ipv6-addr"
        labels = sorted(set(rec.get("tags", [])) | set(rec.get("services", [])))
        desc = (
            f"Attacked {rec['sensors']} Mirage honeypots in {rec['networks']} networks; "
            f"services: {', '.join(rec.get('services', [])) or 'unknown'}."
        )
        ind = add(
            _indicator(
                f"Mirage attacker {rec['ip']}",
                f"[{family}:value = '{escape(rec['ip'])}']",
                rec,
                # Shared VPN and Tor egress: anonymization context, not a malicious-activity block signal.
                "anonymization" if anonymizer(rec) else "malicious-activity",
                description=desc,
                confidence=int(rec["confidence"]),
                **({"labels": labels} if labels else {}),
            )
        )
        for technique in rec.get("attack", []):
            add(_relationship("indicates", ind, add(_attack_pattern(technique, names))))
        for cve in rec.get("cves", []):
            add(_relationship("related-to", ind, add(_vulnerability(cve, kev.get(cve, False)))))
    for rec in s.lists["urls"]:
        add(
            _indicator(
                f"Mirage {rec['kind']} URL",
                f"[url:value = '{escape(rec['url'])}']",
                rec,
                description=f"Seen in exploit payloads by {rec['sources']} sources.",
                labels=[rec["kind"]],
            )
        )
    for rec in s.lists["domains"]:
        add(
            _indicator(
                "Mirage payload domain",
                f"[domain-name:value = '{escape(rec['domain'])}']",
                rec,
                description=f"Hosts payloads seen by {rec['sources']} sources.",
            )
        )
    for rec in s.lists["hashes"]:
        add(
            _indicator(
                "Mirage payload file",
                f"[file:hashes.'SHA-256' = '{escape(rec['sha256'])}']",
                rec,
                description=f"Delivered by payload URLs; seen by {rec['sources']} sources.",
            )
        )
    for cve, is_kev in kev.items():
        add(_vulnerability(cve, is_kev))
    return {"type": "bundle", "id": f"bundle--{uid('bundle', s.day)}", "objects": [objects[k] for k in sorted(objects)]}


def render(s: Snapshot) -> list[Artifact]:
    b = bundle(s)
    return [
        Artifact(
            "latest/stix/mirage.json",
            dumps(b),
            "stix-2.1",
            len(b["objects"]),
            "7d",
            ("opencti", "sentinel", "misp", "taxii-import"),
        )
    ]
