import base64
import gzip
import io
import tarfile

from . import BASE_URL
from .benign import alertable_ua, distinctive_path
from .common import Artifact, Snapshot, high_confidence, lines, network

ZEEK_HEADER = "#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\tmeta.url"
SOURCE = "mirage-feed"
CATEGORY_ID = 1
CATEGORY = "MirageAttacker"
# The README's high-confidence rule matches scores above this.
HIGH_SCORE = 80
THRESHOLD = "threshold:type limit,track by_src,count 1,seconds 3600;"
RULES = f"""\
alert ip any any -> $HOME_NET any (msg:"Mirage feed: known attacker"; iprep:src,{CATEGORY},>,0; \
{THRESHOLD} classtype:misc-attack; sid:1900001; rev:2;)
alert http any any -> $HOME_NET any (msg:"Mirage feed: attacker user-agent"; flow:established,to_server; \
http.user_agent; dataset:isset,mirage-uas,type string,load datasets/uas.lst; {THRESHOLD} classtype:misc-activity; \
sid:1900002; rev:1;)
alert http any any -> $HOME_NET any (msg:"Mirage feed: path probed by attackers"; flow:established,to_server; \
http.uri.raw; dataset:isset,mirage-paths,type string,load datasets/paths.lst; {THRESHOLD} classtype:misc-activity; \
sid:1900003; rev:2;)
"""
# Suricata refuses a filesha256 list with no hashes, so the rule is left out while the list is empty.
HASH_RULE = """\
alert http any any -> any any (msg:"Mirage feed: known payload SHA-256"; flow:established; \
filesha256:datasets/sha256.lst; classtype:trojan-activity; sid:1900004; rev:1;)
"""


# suricata-update ruleset: datasets instead of iprep, so it loads without suricata.yaml changes.
BUNDLE = "latest/suricata/mirage.tar.gz"
BUNDLE_RULES = f"""\
alert ip any any -> $HOME_NET any (msg:"Mirage feed: known attacker"; ip.src; \
dataset:isset,mirage-ips,type ipv4,load datasets/ips.lst; {THRESHOLD} classtype:misc-attack; sid:3510001; rev:1;)
alert http any any -> $HOME_NET any (msg:"Mirage feed: attacker user-agent"; flow:established,to_server; \
http.user_agent; dataset:isset,mirage-uas,type string,load datasets/uas.lst; {THRESHOLD} classtype:misc-activity; \
sid:3510002; rev:1;)
alert http any any -> $HOME_NET any (msg:"Mirage feed: path probed by attackers"; flow:established,to_server; \
http.uri.raw; dataset:isset,mirage-paths,type string,load datasets/paths.lst; {THRESHOLD} classtype:misc-activity; \
sid:3510003; rev:1;)
"""
BUNDLE_HASH_RULE = """\
alert http any any -> any any (msg:"Mirage feed: known payload SHA-256"; flow:established; \
filesha256:datasets/sha256.lst; classtype:trojan-activity; sid:3510004; rev:1;)
"""


def bundle(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buf, mtime=0) as gz, tarfile.open(fileobj=gz, mode="w") as tar:
        for name, data in sorted(files.items()):
            info = tarfile.TarInfo(f"rules/{name}")
            info.size, info.mode = len(data), 0o644
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _zeek_value(value: str) -> str:
    return value.split("://", 1)[1] if "://" in value else value


def zeek(s: Snapshot) -> bytes:
    ips = []
    for r in s.blockable("7d"):
        kind = "Intel::ADDR" if network(r["ip"]).version == 4 else "Intel::SUBNET"
        ips.append((r["ip"], kind, f"attacker confidence={r['confidence']}"))
    rows = [(_zeek_value(r["url"]), "Intel::URL", f"{r['kind']} url") for r in s.lists["urls"]]
    rows += [(r["domain"], "Intel::DOMAIN", "payload domain") for r in s.lists["domains"]]
    rows += [(r["sha256"], "Intel::FILE_HASH", "payload sha256") for r in s.lists["hashes"]]
    rows += [(ua, "Intel::SOFTWARE", "attacker user-agent") for ua in _alertable_uas(s)]
    body = [ZEEK_HEADER] + ["\t".join((v, k, SOURCE, d, BASE_URL)) for v, k, d in ips + sorted(set(rows))]
    return lines(body)


def _alertable_uas(s: Snapshot) -> list[str]:
    return [r["value"] for r in s.lists["user_agents"] if alertable_ua(r["value"])]


def _score(r: dict) -> int:
    score = min(127, max(1, (int(r["confidence"]) * 127 + 50) // 100))
    return score if high_confidence(r) else min(score, HIGH_SCORE)


def _b64(values) -> list[str]:
    return [base64.b64encode(v.encode()).decode() for v in sorted(set(values))]


def render(s: Snapshot) -> list[Artifact]:
    ips = s.blockable("7d")
    iprep = [f"{r['ip']},{CATEGORY_ID},{_score(r)}" for r in ips]
    v4 = [r["ip"] for r in ips if network(r["ip"]).version == 4]
    sha = sorted({r["sha256"] for r in s.lists["hashes"]})
    paths = _b64(r["value"] for r in s.lists["paths"] if distinctive_path(r["value"], r.get("cves")))
    uas = _b64(_alertable_uas(s))
    zeek_data = zeek(s)
    rules = RULES + (HASH_RULE if sha else "")
    datasets = {"ips.lst": lines(v4), "paths.lst": lines(paths), "uas.lst": lines(uas), "sha256.lst": lines(sha)}
    bundle_rules = BUNDLE_RULES + (BUNDLE_HASH_RULE if sha else "")
    tarball = bundle({"mirage.rules": bundle_rules.encode()} | {f"datasets/{k}": v for k, v in datasets.items()})
    suri = ("suricata",)
    return [
        Artifact("latest/zeek/mirage.intel", zeek_data, "zeek-intel", zeek_data.count(b"\n") - 1, "7d", ("zeek",)),
        Artifact(
            "latest/suricata/categories.txt",
            f"{CATEGORY_ID},{CATEGORY},Mirage feed attacker IPs\n".encode(),
            "suricata-iprep-categories",
            1,
            None,
            suri,
        ),
        Artifact("latest/suricata/mirage-iprep.list", lines(iprep), "suricata-iprep", len(iprep), "7d", suri),
        *(
            Artifact(f"latest/suricata/datasets/{name}", datasets[name], "suricata-dataset", n, window, suri)
            for name, n, window in (
                ("ips.lst", len(v4), "7d"),
                ("sha256.lst", len(sha), "30d"),
                ("paths.lst", len(paths), "7d"),
                ("uas.lst", len(uas), "7d"),
            )
        ),
        Artifact("latest/suricata/mirage.rules", rules.encode(), "suricata-rules", rules.count("sid:"), None, suri),
        Artifact(BUNDLE, tarball, "suricata-update", bundle_rules.count("sid:"), "7d", ("suricata", "suricata-update")),
    ]
