import base64
import binascii
import csv
import gzip
import ipaddress
import json
import re
import unicodedata
import urllib.parse
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from . import lookup
from .common import parse_ts
from .netlist import CANARY, DEFAULT_ALLOWLIST, Allowlist

RECORD_SCHEMA = Path(__file__).resolve().parent.parent / "schema" / "record.schema.json"
# path -> (family, form) where form "bare" is a host address and "cidr" a /32 or /64 network
IP_LISTS = {
    "latest/ipv4-1d.txt": (4, "bare"),
    "latest/ipv4-7d.txt": (4, "bare"),
    "latest/ipv4-30d.txt": (4, "bare"),
    "latest/ipv4-top1k.txt": (4, "bare"),
    "latest/ipv4-top10k.txt": (4, "bare"),
    "latest/ipv4-7d-cidr32.txt": (4, "cidr"),
    "latest/ipv6-7d.txt": (6, "cidr"),
    "latest/ipv4-added-1d.txt": (4, "bare"),
    "latest/ipv4-removed-1d.txt": (4, "bare"),
}
ANONYMIZERS = "latest/anonymizers-7d.txt"
ADDED, REMOVED = "latest/ipv4-added-1d.txt", "latest/ipv4-removed-1d.txt"
SCANNER_LISTS = {"latest/known-scanners-ipv4.txt": 4, "latest/known-scanners-ipv6.txt": 6}
IP_CSVS = ("latest/attackers-7d.csv", "latest/attackers-ipv4-7d.csv", "latest/defender/defender-top500.csv")
REQUIRED = (
    *IP_LISTS,
    *SCANNER_LISTS,
    *IP_CSVS,
    ANONYMIZERS,
    "latest/urls-7d.txt",
    "latest/domains-7d.txt",
    "latest/hashes-sha256-30d.txt",
    "latest/user-agents-7d.txt",
    "latest/paths-7d.txt",
    "latest/passwords-top100.txt",
    "latest/cves-7d.csv",
    "latest/fingerprints.csv",
    "latest/hassh.csv",
    "latest/records-7d.ndjson.gz",
    "latest/stix/mirage.json",
    "misp/manifest.json",
    "misp/hashes.csv",
    "latest/zeek/mirage.intel",
    "latest/suricata/categories.txt",
    "latest/suricata/mirage-iprep.list",
    "latest/suricata/mirage.rules",
    "latest/mikrotik/mirage-7d.rsc",
    "latest/nft/mirage.nft",
    "latest/ipset/mirage.ipset",
    "latest/crowdsec/mirage-7d.csv",
    "schema/record.schema.json",
    "feed.json",
    "stats.json",
    "history.json",
    "og.png",
    "og-github.png",
    "SHA256SUMS",
)
HOST_PREFIX = {4: 32, 6: 64}
# Size limit per list versus the previous build; changes under MIN_CHANGE entries are ignored.
DELTA_LIMITS = {
    "latest/ipv4-1d.txt": 0.50,
    "latest/ipv4-7d.txt": 0.30,
    "latest/ipv4-30d.txt": 0.30,
    "latest/ipv6-7d.txt": 0.30,
    "latest/ipv4-top1k.txt": 0.30,
    "latest/ipv4-top10k.txt": 0.30,
    "latest/urls-7d.txt": 0.30,
    "latest/domains-7d.txt": 0.30,
}
MIN_CHANGE = 20
# A 7-day window turns over roughly 1/7 per day; >40% new and >40% gone at once means a different list.
CHURN_LIMIT = 0.40
CHURN_LISTS = (
    "latest/ipv4-7d.txt",
    "latest/ipv4-30d.txt",
    "latest/ipv6-7d.txt",
    "latest/ipv4-top1k.txt",
    "latest/ipv4-top10k.txt",
)
CONCENTRATION_MIN = 200
# Hosting ASNs legitimately dominate some days; a poisoning swap shows up as a jump over yesterday's share.
MAX_ASN_SHARE, ASN_JUMP = 0.25, 0.10
MAX_SLASH16_SHARE, SLASH16_JUMP = 0.05, 0.05
STIX_IP = re.compile(r"\[ipv[46]-addr:value = '([^']+)'\]")
BASE64_FILES = ("latest/suricata/datasets/paths.lst", "latest/suricata/datasets/uas.lst")
LEAK_ENV = ("MIRAGE_LEAK_PATTERNS", "MIRAGE_LEAK_LITERALS")


def _read(path: Path) -> bytes:
    data = path.read_bytes()
    return gzip.decompress(data) if path.suffix == ".gz" else data


def _lines(out: Path, rel: str) -> list[str]:
    return (out / rel).read_text(encoding="utf-8").splitlines()


def _records(out: Path) -> list[dict]:
    return [json.loads(line) for line in _read(out / "latest/records-7d.ndjson.gz").splitlines()]


def _guess(rel: str, value: str) -> tuple[str, str, int, str]:
    return (rel, value, 6, "cidr") if ":" in value else (rel, value, 4, "bare")


def _csv_column(out: Path, rel: str, column: str) -> list[str]:
    with (out / rel).open(newline="", encoding="utf-8") as fh:
        return [row[column] for row in csv.DictReader(fh)]


def _misp_ips(out: Path) -> dict[str, list[dict]]:
    """Live ip-src attributes per event file; attributes sent as deleted only tell MISP to drop them."""
    found = {}
    for path in sorted((out / "misp").glob("*.json")):
        if path.name != "manifest.json":
            attrs = json.loads(path.read_text(encoding="utf-8"))["Event"].get("Attribute", [])
            found[f"misp/{path.name}"] = [a for a in attrs if a["type"] == "ip-src" and not a.get("deleted")]
    return found


def _ip_entries(out: Path) -> list[tuple[str, str, int, str]]:
    """(file, value, expected family, form) for every published attacker IP."""
    entries = []
    for rel, (family, form) in IP_LISTS.items():
        entries += [(rel, v, family, form) for v in _lines(out, rel)]
    entries += [_guess(ANONYMIZERS, v) for v in _lines(out, ANONYMIZERS)]
    entries += [
        _guess("latest/records-7d.ndjson.gz", r["value"]) for r in _records(out) if r.get("type") in ("ipv4", "ipv6")
    ]
    for rel in IP_CSVS:
        column = "IndicatorValue" if "defender" in rel else "ip"
        entries += [_guess(rel, v) for v in _csv_column(out, rel, column)]
    rel = "latest/suricata/mirage-iprep.list"
    entries += [_guess(rel, line.split(",", 1)[0]) for line in _lines(out, rel)]
    for rel, attrs in _misp_ips(out).items():
        entries += [_guess(rel, a["value"]) for a in attrs]
    return entries


def check_ips(out: Path, allowlist: Allowlist, canary: Allowlist) -> list[str]:
    entries = _ip_entries(out)
    week, added, removed = (set(_lines(out, rel)) for rel in ("latest/ipv4-7d.txt", ADDED, REMOVED))
    errors = [f"{ADDED}: {v} is not in ipv4-7d.txt" for v in sorted(added - week)]
    errors += [f"{REMOVED}: {v} is still in ipv4-7d.txt" for v in sorted(removed & week)]
    for (rel, value), n in sorted(Counter((e[0], e[1]) for e in entries).items()):
        if n > 1:
            errors.append(f"{rel}: duplicate entry {value}")
    for rel, value, family, form in entries:
        try:
            net = ipaddress.ip_network(value, strict=True)
        except ValueError:
            errors.append(f"{rel}: not an IP or network: {value!r}")
            continue
        canonical = str(net.network_address) if form == "bare" else str(net)
        if net.version != family:
            errors.append(f"{rel}: IPv{net.version} entry in IPv{family} list: {value}")
        elif net.prefixlen != HOST_PREFIX[family]:
            errors.append(f"{rel}: only /32 and /64 entries allowed, got {value}")
        elif value != canonical:
            errors.append(f"{rel}: non-canonical entry {value}, want {canonical}")
        elif hit := canary.hit(net):
            errors.append(f"{rel}: canary address {hit} published")
        # Removals tell consumers to unblock, so a newly allowlisted address belongs there.
        elif rel != REMOVED and (hit := allowlist.hit(net)):
            errors.append(f"{rel}: {value} overlaps allowlisted {hit}")
    return errors


def _blocklists(out: Path) -> dict[str, set[str]]:
    """Entries, by path, of every file a firewall, IDS or EDR blocks or alerts on."""
    found = {rel: set(_lines(out, rel)) for rel in IP_LISTS if rel != REMOVED}
    found["latest/ipv4-7d-cidr32.txt"] = {v.removesuffix("/32") for v in found["latest/ipv4-7d-cidr32.txt"]}
    found["latest/defender/defender-top500.csv"] = set(_csv_column(out, IP_CSVS[2], "IndicatorValue"))
    found["latest/crowdsec/mirage-7d.csv"] = set(_csv_column(out, "latest/crowdsec/mirage-7d.csv", "value"))
    found["latest/suricata/mirage-iprep.list"] = {
        line.split(",", 1)[0] for line in _lines(out, "latest/suricata/mirage-iprep.list")
    }
    found["latest/suricata/datasets/ips.lst"] = set(_lines(out, "latest/suricata/datasets/ips.lst"))
    zeek = [line.split("\t") for line in _lines(out, "latest/zeek/mirage.intel")[1:]]
    found["latest/zeek/mirage.intel"] = {r[0] for r in zeek if r[1] in ("Intel::ADDR", "Intel::SUBNET")}
    found["latest/nft/mirage.nft"] = {
        ip
        for line in _lines(out, "latest/nft/mirage.nft")
        if line.startswith("add element ")
        for ip in line.split("{ ", 1)[1].removesuffix(" }").split(", ")
    }
    found["latest/ipset/mirage.ipset"] = {
        line.split()[2] for line in _lines(out, "latest/ipset/mirage.ipset") if line.startswith("add ")
    }
    for rel, attrs in _misp_ips(out).items():
        found[rel] = {a["value"] for a in attrs if a.get("to_ids")}
    bundle = json.loads((out / "latest/stix/mirage.json").read_text(encoding="utf-8"))
    found["latest/stix/mirage.json"] = {
        m.group(1)
        for o in bundle.get("objects", [])
        if o.get("type") == "indicator" and "malicious-activity" in o.get("indicator_types", [])
        if (m := STIX_IP.fullmatch(o.get("pattern", "")))
    }
    rsc = (out / "latest/mikrotik/mirage-7d.rsc").read_text(encoding="utf-8")
    found["latest/mikrotik/mirage-7d.rsc"] = set(re.findall(r"add list=mirage-feed address=(\S+)", rsc))
    return found


def check_anonymizers(out: Path) -> list[str]:
    anon = set(_lines(out, ANONYMIZERS))
    return [
        f"{rel}: anonymizer {value} is in a block list"
        for rel, values in sorted(_blocklists(out).items())
        for value in sorted(anon & values)
    ]


def check_scanners(out: Path, canary: Allowlist) -> list[str]:
    # An attacker reclassified as a scanner leaves through the removal list, so that list does not count.
    attackers = {e[1] for e in _ip_entries(out) if e[0] != REMOVED}
    errors = []
    for rel, family in SCANNER_LISTS.items():
        values = _lines(out, rel)
        errors += [f"{rel}: duplicate entry {v}" for v, n in sorted(Counter(values).items()) if n > 1]
        for value in values:
            try:
                net = ipaddress.ip_network(value, strict=True)
            except ValueError:
                errors.append(f"{rel}: not an IP or network: {value!r}")
                continue
            single = net.prefixlen == 32 if family == 4 else net.prefixlen >= 64
            want = str(net.network_address) if family == 4 else str(net)
            if net.version != family or not single or value != want:
                errors.append(f"{rel}: only canonical /32 IPv4 or /64-or-longer IPv6 allowed, got {value}")
            elif canary.hit(net):
                errors.append(f"{rel}: canary address published")
            elif (str(net.supernet(new_prefix=64)) if family == 6 else value) in attackers:
                errors.append(f"{rel}: {value} is also listed as an attacker")
    return errors


def normalise(text: str) -> str:
    text = unicodedata.normalize("NFKC", urllib.parse.unquote(text))
    return "".join(c for c in text if unicodedata.category(c) != "Cf").casefold()


def _texts(out: Path):
    for path in sorted(p for p in out.rglob("*") if p.is_file()):
        rel = str(path.relative_to(out))
        text = _read(path).decode("utf-8", "replace")
        if rel in BASE64_FILES:
            try:
                text += "\n" + "\n".join(base64.b64decode(v).decode("utf-8", "replace") for v in text.split())
            except (binascii.Error, ValueError):
                yield rel, None
                continue
        yield rel, normalise(text)


def check_leaks(out: Path, patterns: list[str], literals: list[str], required: bool) -> list[str]:
    if not patterns and not literals:
        return ["leak rules empty (MIRAGE_LEAK_PATTERNS, MIRAGE_LEAK_LITERALS)"] if required else []
    compiled = []
    for i, pattern in enumerate(patterns, 1):
        try:
            # Raw source: normalising it would turn \D into \d and %2e into a wildcard.
            compiled.append(re.compile(pattern, re.IGNORECASE))
        except re.error:
            return [f"leak pattern #{i} is not a valid regex"]
    needles = [normalise(v) for v in literals]
    errors = []
    for rel, text in _texts(out):
        if text is None or any(rx.search(text) for rx in compiled) or any(n in text for n in needles):
            errors.append(f"leak in {rel}")
    return errors


def _sizes(out: Path, prev: Path, rel: str) -> tuple[set[str], set[str]] | None:
    if not (prev / rel).is_file():
        return None
    return set(_lines(out, rel)), set(_lines(prev, rel))


def check_delta(out: Path, prev: Path | None, allow_delta: bool, bootstrap: bool) -> list[str]:
    if bootstrap:
        return []
    if not prev or not (prev / "feed.json").is_file():
        return ["no previous data to compare against; pass --bootstrap only for the first publish"]
    if allow_delta:
        return []
    errors = []
    for rel, limit in DELTA_LIMITS.items():
        if not (pair := _sizes(out, prev, rel)):
            continue
        new, old = len(pair[0]), len(pair[1])
        if abs(new - old) >= MIN_CHANGE and (not old or abs(new - old) / old > limit):
            change = f"{(new - old) / old:+.1%}" if old else "from empty"
            errors.append(f"{rel}: size {old} -> {new} ({change}), limit ±{limit:.0%}; use --allow-delta if expected")
    for rel in CHURN_LISTS:
        if not (pair := _sizes(out, prev, rel)) or min(len(pair[0]), len(pair[1])) < MIN_CHANGE:
            continue
        cur, old = pair
        added, gone = len(cur - old) / len(cur), len(old - cur) / len(old)
        if added > CHURN_LIMIT and gone > CHURN_LIMIT:
            errors.append(
                f"{rel}: {added:.0%} new and {gone:.0%} gone since the previous build, limit {CHURN_LIMIT:.0%}"
            )
    return errors


def _shares(keys: list[str]) -> dict[str, float]:
    return {k: n / len(keys) for k, n in Counter(keys).items()} if keys else {}


def _over(cur: dict[str, float], prev: dict[str, float], floor: float, jump: float) -> list[tuple[str, float, float]]:
    limits = {k: max(floor, prev.get(k, 0) + jump) for k in cur}
    return [(k, v, limits[k]) for k, v in sorted(cur.items()) if v > limits[k]]


def check_concentration(rows: list[tuple[str, str]], prev_rows: list[tuple[str, str]] = ()) -> list[str]:
    """rows: (ip, asn) for the 7-day list; prev_rows: the same for the previous publish."""
    if len(rows) < CONCENTRATION_MIN:
        return []

    def by_asn(r):
        return _shares([asn for _, asn in r if asn])

    def by_block(r):
        return _shares([str(ipaddress.ip_network(f"{ip}/16", strict=False)) for ip, _ in r if ":" not in ip])

    asns = _over(by_asn(rows), by_asn(prev_rows), MAX_ASN_SHARE, ASN_JUMP)
    blocks = _over(by_block(rows), by_block(prev_rows), MAX_SLASH16_SHARE, SLASH16_JUMP)
    return [
        *(f"AS{k} holds {v:.0%} of the 7-day list, limit {lim:.0%}" for k, v, lim in asns),
        *(f"{k} holds {v:.0%} of the IPv4 list, limit {lim:.0%}" for k, v, lim in blocks),
    ]


def check_schema(out: Path) -> list[str]:
    import jsonschema

    validator = jsonschema.Draft202012Validator(
        json.loads(RECORD_SCHEMA.read_text()), format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER
    )
    return [
        f"records-7d.ndjson.gz line {i}: {err.message}"
        for i, rec in enumerate(_records(out), 1)
        for err in validator.iter_errors(rec)
    ]


SDO_REQUIRED = ("type", "spec_version", "id", "created", "modified")
TYPE_REQUIRED = {
    "indicator": ("pattern", "pattern_type", "valid_from"),
    "relationship": ("relationship_type", "source_ref", "target_ref"),
    "identity": ("name",),
    "vulnerability": ("name",),
    "attack-pattern": ("name",),
}


def check_stix(out: Path) -> list[str]:
    from .stix import TLP_CLEAR_ID

    bundle = json.loads((out / "latest/stix/mirage.json").read_text())
    if bundle.get("type") != "bundle" or not str(bundle.get("id", "")).startswith("bundle--"):
        return ["stix: not a STIX bundle"]
    objects = bundle.get("objects", [])
    ids = [o.get("id") for o in objects]
    errors = [f"stix: duplicate id {i}" for i, n in sorted(Counter(ids).items()) if n > 1]
    known = set(ids)
    if TLP_CLEAR_ID not in known:
        errors.append("stix: TLP:CLEAR marking-definition missing")
    for o in objects:
        if not str(o.get("id", "")).startswith(f"{o.get('type')}--"):
            errors.append(f"stix: id {o.get('id')} does not match type {o.get('type')}")
        if o.get("type") == "marking-definition":
            continue
        required = SDO_REQUIRED + TYPE_REQUIRED.get(o.get("type"), ())
        errors += [f"stix: {o.get('id')} missing {p}" for p in required if p not in o]
        if TLP_CLEAR_ID not in o.get("object_marking_refs", []):
            errors.append(f"stix: {o.get('id')} lacks TLP:CLEAR marking")
        for ref in ("created_by_ref", "source_ref", "target_ref"):
            if ref in o and o[ref] not in known:
                errors.append(f"stix: {o['id']} {ref} points to missing {o[ref]}")
    return errors


def _generated(root: Path) -> str:
    return json.loads((root / "feed.json").read_text(encoding="utf-8"))["generated"]


def check_rollback(out: Path, prev: Path | None) -> list[str]:
    if not prev or not (prev / "feed.json").is_file():
        return []
    cur, old = _generated(out), _generated(prev)
    if cur > old:
        return []
    return [f"snapshot generated {cur} is not newer than the previous build's {old}; use --allow-rollback if intended"]


def check_expiry(out: Path) -> list[str]:
    """Indicators must still be valid when they are imported."""
    now = parse_ts(_generated(out))
    errors = []
    with (out / IP_CSVS[2]).open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            if datetime.strptime(row["ExpirationTime"], "%Y-%m-%dT%H:%M:%S.0Z").replace(tzinfo=UTC) <= now:
                errors.append(f"{IP_CSVS[2]}: {row['IndicatorValue']} expires {row['ExpirationTime']}")
    stamp = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    for o in json.loads((out / "latest/stix/mirage.json").read_text(encoding="utf-8")).get("objects", []):
        if o.get("type") == "indicator" and o.get("valid_until", "9") <= stamp:
            errors.append(f"stix: {o['id']} expires {o['valid_until']}")
        if o.get("modified", "9") < o.get("created", ""):
            errors.append(f"stix: {o['id']} modified before created")
    return errors


def check_lookup(out: Path) -> list[str]:
    """The /ip shards hold exactly the addresses of the IP lists, each with its list memberships."""
    want: dict[str, list[str]] = {}
    for name in lookup.LISTS:
        for value in _lines(out, f"latest/{name}"):
            want.setdefault(value, []).append(name)
    errors, have = [], {}
    for path in sorted((out / lookup.DIR).rglob("*.json")):
        rel = str(path.relative_to(out))
        for value, entry in json.loads(path.read_text(encoding="utf-8")).items():
            have[value] = entry.get("lists")
            if lookup.shard(value) != rel:
                errors.append(f"{rel}: {value} belongs in {lookup.shard(value)}")
    errors += [f"{lookup.DIR}: {v} missing" for v in sorted(want.keys() - have.keys())]
    errors += [f"{lookup.DIR}: {v} is in no list" for v in sorted(have.keys() - want.keys())]
    errors += [
        f"{lookup.DIR}: {v} lists {have[v]}, want {want[v]}"
        for v in sorted(want.keys() & have.keys())
        if have[v] != want[v]
    ]
    return errors


def _ip_asn_rows(root: Path) -> list[tuple[str, str]]:
    return list(zip(_csv_column(root, IP_CSVS[0], "ip"), _csv_column(root, IP_CSVS[0], "asn"), strict=True))


def run(
    out: Path,
    prev: Path | None = None,
    allowlist: Path = DEFAULT_ALLOWLIST,
    *,
    allow_delta: bool = False,
    bootstrap: bool = False,
    allow_rollback: bool = False,
    leak_patterns: list[str] = (),
    leak_literals: list[str] = (),
    require_leak_rules: bool = False,
    canary: Path = CANARY,
) -> list[str]:
    missing = [f"missing output {rel}" for rel in REQUIRED if not (out / rel).is_file()]
    if missing:
        return missing
    rows = _ip_asn_rows(out)
    prev_rows = _ip_asn_rows(prev) if prev and (prev / IP_CSVS[0]).is_file() else []
    canaries = Allowlist(canary)
    return [
        *check_leaks(out, list(leak_patterns), list(leak_literals), require_leak_rules),
        *check_ips(out, Allowlist(allowlist), canaries),
        *check_scanners(out, canaries),
        *check_anonymizers(out),
        *check_delta(out, prev, allow_delta, bootstrap),
        *([] if allow_rollback else check_rollback(out, prev)),
        *([] if allow_delta else check_concentration(rows, prev_rows)),
        *check_schema(out),
        *check_stix(out),
        *check_expiry(out),
        *check_lookup(out),
    ]
