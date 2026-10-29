import csv
import io
import ipaddress
import json
import re
import unicodedata
import uuid
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from . import NAMESPACE, SCHEMA, benign, kev

TTL = timedelta(days=7)
WINDOWS = {"1d": ("1d",), "7d": ("1d", "7d"), "30d": ("1d", "7d", "30d")}
CSV_RISKY = ("=", "+", "-", "@", "\t", "\r")
BAD_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp"})
LISTS = ("ips", "scanners", "cves", "urls", "domains", "hashes", "fingerprints", "user_agents", "paths", "passwords")
KEYS = {"cves": "cve", "urls": "url", "domains": "domain", "hashes": "sha256", "fingerprints": "value",
        "user_agents": "value", "paths": "value", "passwords": "value"}  # fmt: skip
POLICY_KEYS = ("min_sensors", "min_networks", "min_sources", "delay_hours", "ttl_days", "ipv6_prefix")
OBSERVED_KEYS = ("ips", "asns", "countries", "events", "cves", "urls", "credential_pairs", "hashes")
# JA4 (TLS client) only: the rest of JA4+ is under the FoxIO licence.
JA4_TYPES = frozenset({"ja4"})
ANONYMIZER_TAGS = frozenset({"vpn-exit", "tor-exit"})
MAX_BREAKDOWN = 50
IP_COUNTS = {"sensors": 3, "networks": 2, "confidence": 0, "hits": 0}
HOST_NETS = ((4, 32), (6, 64))
# [0-9], not \d: Python's \d also matches non-ASCII digits.
DAY = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
GENERATED = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
HOUR = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:00:00Z")
TECHNIQUE = re.compile(r"T[0-9]{4}(\.[0-9]{3})?")
CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
DIGITS = re.compile(r"[0-9]{1,18}")
SHA256 = re.compile(r"[0-9a-f]{64}")
TOKEN = re.compile(r"[a-z0-9_-]{1,32}")
# XX is Cloudflare's "unknown"; T1 (Tor) already fails the pattern.
COUNTRY = re.compile(r"(?!XX)[A-Z]{2}")
NAME = re.compile(r"[\w .,()/&'+-]{1,80}")


class SnapshotError(ValueError):
    pass


@dataclass(frozen=True)
class Artifact:
    path: str
    data: bytes
    format: str
    count: int
    window: str | None = None
    consumers: tuple[str, ...] = ()


def uid(*parts: str) -> str:
    return str(uuid.uuid5(NAMESPACE, ":".join(parts)))


def parse_ts(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def expiry(last_seen: str, generated: str) -> datetime:
    # Never already expired on import: a record last seen near the window's edge still gets a day.
    return max(parse_ts(last_seen) + TTL, parse_ts(generated) + timedelta(days=1))


def network(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    return ipaddress.ip_network(value, strict=True)


def canonical(value: str) -> str:
    net = network(value)
    return str(net.network_address) if net.version == 4 and net.prefixlen == 32 else str(net)


def ip_key(value: str) -> tuple[int, int, int]:
    net = network(value)
    return net.version, int(net.network_address), net.prefixlen


def dumps(obj, indent: int | None = None) -> bytes:
    separators = (",", ": ") if indent else (",", ":")
    text = json.dumps(obj, sort_keys=True, ensure_ascii=False, indent=indent, separators=separators)
    return (text + "\n").encode()


def lines(values) -> bytes:
    values = list(values)
    return ("\n".join(values) + "\n").encode() if values else b""


def cell(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        value = ";".join(str(v) for v in value)
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(CSV_RISKY) else text


def csv_bytes(header, rows) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\r\n")
    writer.writerow(header)
    writer.writerows([cell(v) for v in row] for row in rows)
    return buf.getvalue().encode()


def _bad_chars(value) -> bool:
    if isinstance(value, str):
        return any(unicodedata.category(c) in BAD_CATEGORIES for c in value)
    if isinstance(value, list):
        return any(_bad_chars(v) for v in value)
    if isinstance(value, dict):
        return any(_bad_chars(v) for v in value.values())
    return False


def _int(value, lo: int = 0) -> int | None:
    if isinstance(value, str) and DIGITS.fullmatch(value):
        value = int(value)
    return None if isinstance(value, bool) or not isinstance(value, int) or value < lo else value


def _ints(raw, keys) -> dict[str, int]:
    raw = raw if isinstance(raw, dict) else {}
    return {k: n for k in keys if (n := _int(raw.get(k))) is not None}


def _breakdown(rows, key: str, pattern: re.Pattern, counts: tuple[str, ...]) -> list[dict]:
    out = []
    for row in rows if isinstance(rows, list) else []:
        if isinstance(row, dict) and isinstance(row.get(key), str) and pattern.fullmatch(row[key]):
            entry = {key: row[key], **{c: _int(row.get(c, 0)) for c in counts}}
            if None in entry.values():
                continue
            if isinstance(row.get("name"), str) and NAME.fullmatch(row["name"]):
                entry["name"] = row["name"]
            out.append(entry)
    return out[:MAX_BREAKDOWN]


# Stats and policy are informational: a bad value is left out rather than failing the build.
def clean_stats(raw) -> dict:
    raw = raw if isinstance(raw, dict) else {}
    return {
        "observed": _ints(raw.get("observed"), OBSERVED_KEYS),
        "published": {},
        "attack": _breakdown(raw.get("attack"), "technique", TECHNIQUE, ("events", "ips")),
        "services": _breakdown(raw.get("services"), "service", TOKEN, ("ips",)),
        "countries": _breakdown(raw.get("countries"), "country", COUNTRY, ("ips",)),
    }


def clean_policy(raw) -> dict:
    return _ints(raw, POLICY_KEYS)


def _count(value, lo: int = 0) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= lo


def _stamp(value, pattern: re.Pattern) -> bool:
    try:
        return isinstance(value, str) and bool(pattern.fullmatch(value)) and bool(parse_ts(value))
    except ValueError:
        return False


def _seen(rec: dict, required: bool) -> bool:
    first, last = rec.get("first_seen"), rec.get("last_seen")
    if not required and first is None and last is None:
        return True
    pattern = HOUR if required else GENERATED
    return _stamp(first, pattern) and _stamp(last, pattern) and first <= last


def _clamp(rec: dict, generated: str) -> dict:
    """Producer clock skew: a sighting after the snapshot would make a STIX indicator's created later than modified."""
    late = [k for k in ("first_seen", "last_seen") if isinstance(rec.get(k), str) and rec[k] > generated]
    return {**rec, **dict.fromkeys(late, generated[:14] + "00:00Z")}


def _valid(kind: str, rec: dict) -> bool:
    """Shape and benign-value filters for the non-IP lists; failing records are dropped."""
    value = rec.get(KEYS[kind])
    if not isinstance(value, str) or not value or _bad_chars(rec):
        return False
    # Records carry what the schema requires of them: url, domain and sha256 lines in records-7d.ndjson.gz.
    if kind in ("urls", "domains", "hashes"):
        if not (_count(rec.get("sightings")) and _count(rec.get("sources"), 2) and _seen(rec, True)):
            return False
    elif not (_count(rec.get("sources")) and _seen(rec, False)):
        return False
    match kind:
        case "cves":
            return bool(CVE.fullmatch(value))
        case "urls":
            return rec.get("kind") in ("download", "c2") and benign.url_ok(value)
        case "domains":
            return benign.domain_ok(value)
        case "hashes":
            return bool(SHA256.fullmatch(value))
        case "fingerprints":
            kind = rec.get("type")
            return (
                isinstance(kind, str)
                and bool(TOKEN.fullmatch(kind))
                and (kind in JA4_TYPES or kind.startswith("hassh"))
            )
        case "user_agents":
            return benign.user_agent_ok(value)
        case "paths":
            cves = rec.get("cves", [])
            return isinstance(cves, list) and all(isinstance(c, str) for c in cves) and benign.path_ok(value)
    return True


def anonymizer(rec: dict) -> bool:
    return not ANONYMIZER_TAGS.isdisjoint(rec.get("tags", []))


def _ip_cves(ips: list[dict], known: list[dict]) -> list[dict]:
    """cves rows for CVEs cited by published IPs but missing from the snapshot's CVE list."""
    have = {c["cve"] for c in known}
    cited: dict[str, list[dict]] = {}
    for r in ips:
        for cve in r.get("cves", []):
            if cve not in have and CVE.fullmatch(cve):
                cited.setdefault(cve, []).append(r)
    rows = []
    for cve, recs in sorted(cited.items()):
        # An IP's kev flag covers all its CVEs, so it only pins this one when it is the IP's sole CVE.
        pinned = any(r.get("kev") and r["cves"] == [cve] for r in recs)
        rows.append(
            {
                "cve": cve,
                "kev": pinned or cve in kev.catalog(),
                "sources": len(recs),
                "first_seen": min(r["first_seen"] for r in recs),
                "last_seen": max(r["last_seen"] for r in recs),
            }
        )
    return rows


def _tokens(rec: dict, key: str, pattern: re.Pattern) -> list[str]:
    values = rec.get(key)
    return (
        sorted({v for v in values if isinstance(v, str) and pattern.fullmatch(v)}) if isinstance(values, list) else []
    )


def _host(value) -> str | None:
    """The canonical /32 or /64 form of value, or None."""
    try:
        ip = canonical(value)
    except ValueError:
        return None
    net = network(ip)
    return ip if (net.version, net.prefixlen) in HOST_NETS else None


def _check_ip(rec, generated: str) -> dict | None:
    """A schema-shaped copy of one attacker record, or None when it can't be published."""
    if not isinstance(rec, dict) or not isinstance(rec.get("ip"), str):
        return None
    if _bad_chars({k: v for k, v in rec.items() if k != "as_org"}):
        return None
    window = rec.get("window")
    # A string tag could be "vpn-exit": dropping the record beats routing an anonymizer to the block lists.
    if not (isinstance(window, str) and window in WINDOWS and isinstance(rec.get("tags", []), list)):
        return None
    counts = {k: _int(rec.get(k), lo) for k, lo in IP_COUNTS.items()}
    ip = _host(rec["ip"])
    if not ip or None in counts.values() or counts["confidence"] > 100 or not _seen(rec, True):
        return None
    asn, org, country = rec.get("asn"), rec.get("as_org"), rec.get("country")
    return {
        **_clamp(rec, generated),
        **counts,
        "ip": ip,
        "kev": rec.get("kev") is True,
        "asn": asn if _count(asn) else None,
        "as_org": org if isinstance(org, str) and org and not _bad_chars(org) else None,
        "country": country if isinstance(country, str) and COUNTRY.fullmatch(country) else None,
        "services": _tokens(rec, "services", TOKEN),
        "tags": _tokens(rec, "tags", TOKEN),
        "attack": _tokens(rec, "attack", TECHNIQUE),
        "cves": _tokens(rec, "cves", CVE),
    }


def _scanner(rec) -> dict | None:
    if not isinstance(rec, dict) or not isinstance(rec.get("ip"), str) or _bad_chars(rec):
        return None
    ip = _host(rec["ip"])
    return {**rec, "ip": ip} if ip else None


class Snapshot:
    def __init__(self, raw: dict, allowlist=None):
        if not isinstance(raw, dict) or raw.get("schema") != SCHEMA:
            raise SnapshotError(f"unexpected schema, want {SCHEMA!r}")
        generated, day = raw.get("generated"), raw.get("day")
        if not isinstance(generated, str) or not GENERATED.fullmatch(generated):
            raise SnapshotError("generated must be YYYY-MM-DDTHH:MM:SSZ")
        if not isinstance(day, str) or not DAY.fullmatch(day):
            raise SnapshotError("day must be YYYY-MM-DD")
        try:
            gen_day, snap_day = parse_ts(generated).date(), date.fromisoformat(day)
        except ValueError as exc:
            raise SnapshotError(str(exc)) from exc
        if snap_day not in (gen_day, gen_day - timedelta(days=1)):
            raise SnapshotError("day must be the generated date or the day before")
        missing = [k for k in LISTS if not isinstance(raw.get(k), list)]
        if missing:
            raise SnapshotError(f"snapshot missing lists: {', '.join(missing)}")
        self.day: str = day
        self.generated: str = generated
        self.policy = clean_policy(raw.get("policy"))
        self.stats = clean_stats(raw.get("stats"))
        ips = [r for r in (_check_ip(r, generated) for r in raw["ips"]) if r]
        best: dict[str, dict] = {}
        for rec in sorted(ips, key=lambda r: -r["confidence"]):
            best.setdefault(rec["ip"], rec)
        # The allowlist gate stays as a backstop; a range newly allowlisted here must not stall the build.
        allowed = {ip for ip in best if allowlist and allowlist.hit(network(ip))}
        if len(allowed) > max(20, len(best) // 20):
            raise SnapshotError(f"{len(allowed)} of {len(best)} attacker IPs are allowlisted")
        self.lists = {"ips": [r for ip, r in best.items() if ip not in allowed]}
        scanners = [_scanner(r) for r in raw["scanners"]]
        unique: dict[str, dict] = {}
        for rec in filter(None, scanners):
            if rec["ip"] not in best:
                unique.setdefault(rec["ip"], rec)
        self.lists["scanners"] = list(unique.values())
        self.dropped: dict[str, int] = {}
        # A few bad records are dropped; more than that means the producer is broken.
        for kind, kept in (("ips", len(ips)), ("scanners", len(scanners) - scanners.count(None))):
            if n := len(raw[kind]) - kept:
                if n > max(5, len(raw[kind]) // 20):
                    raise SnapshotError(f"{n} of {len(raw[kind])} {kind} records are malformed")
                self.dropped[kind] = n
        if allowed:
            self.dropped["allowlisted"] = len(allowed)
        for kind in LISTS[2:]:
            seen: dict[str, dict] = {}
            for rec in raw[kind]:
                if isinstance(rec, dict) and _valid(kind, rec):
                    seen.setdefault(rec[KEYS[kind]], _clamp(rec, generated))
                else:
                    self.dropped[kind] = self.dropped.get(kind, 0) + 1
            self.lists[kind] = list(seen.values())
        if not self.lists["ips"] or not self.lists["scanners"]:
            raise SnapshotError("ips and scanners must not be empty")
        self.lists["cves"] = [
            {**c, "kev": c.get("kev") is True or c["cve"] in kev.catalog()} for c in self.lists["cves"]
        ]
        self.lists["cves"] += _ip_cves(self.ips_in("7d"), self.lists["cves"])
        week = self.blockable("7d")
        self.stats["published"] = {
            "ips": len(week),
            "active_24h": len(self.blockable("1d")),
            "ips_30d": len(self.blockable("30d")),
            "asns": len({r["asn"] for r in week if r.get("asn") is not None}),
            "countries": len({r["country"] for r in week if r.get("country")}),
            "cves": len(self.lists["cves"]),
            "urls": len(self.lists["urls"]),
            "hashes": len(self.lists["hashes"]),
            "scanners": len(self.lists["scanners"]),
            "fingerprints": len(self.lists["fingerprints"]),
            "anonymizers": len(self.anonymizers()),
        }

    @classmethod
    def load(cls, path: str | Path, allowlist=None) -> "Snapshot":
        try:
            return cls(json.loads(Path(path).read_text(encoding="utf-8")), allowlist)
        except json.JSONDecodeError as exc:
            raise SnapshotError(f"{path}: {exc}") from exc

    def ips_in(self, window: str, version: int | None = None) -> list[dict]:
        recs = [r for r in self.lists["ips"] if r["window"] in WINDOWS[window]]
        if version:
            recs = [r for r in recs if network(r["ip"]).version == version]
        return sorted(recs, key=lambda r: ip_key(r["ip"]))

    def blockable(self, window: str, version: int | None = None) -> list[dict]:
        """IPs for block lists: shared VPN and Tor exits go to anonymizers-7d.txt only."""
        return [r for r in self.ips_in(window, version) if not anonymizer(r)]

    def anonymizers(self) -> list[dict]:
        return [r for r in self.ips_in("7d") if anonymizer(r)]

    def ranked_v4(
        self, limit: int, skip_tags: frozenset[str] = frozenset(), skip_only: frozenset[str] = frozenset()
    ) -> list[dict]:
        pool = [
            r
            for r in self.blockable("7d", 4)
            if skip_tags.isdisjoint(r.get("tags", [])) and not (r.get("tags") and set(r["tags"]) <= skip_only)
        ]
        ranked = sorted(pool, key=lambda r: (-int(r["confidence"]), ip_key(r["ip"])))
        return sorted(ranked[:limit], key=lambda r: ip_key(r["ip"]))
