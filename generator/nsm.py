import base64

from . import BASE_URL
from .common import Artifact, Snapshot, lines, network

ZEEK_HEADER = "#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\tmeta.url"
SOURCE = "mirage-feed"
CATEGORY_ID = 1
CATEGORY = "MirageAttacker"
THRESHOLD = "threshold:type limit,track by_src,count 1,seconds 3600;"
RULES = f"""\
alert ip any any -> $HOME_NET any (msg:"Mirage feed: known attacker"; iprep:src,{CATEGORY},>,50; \
{THRESHOLD} classtype:misc-attack; sid:1900001; rev:1;)
alert http any any -> $HOME_NET any (msg:"Mirage feed: attacker user-agent"; flow:established,to_server; \
http.user_agent; dataset:isset,mirage-uas,type string,load datasets/uas.lst; {THRESHOLD} classtype:misc-activity; \
sid:1900002; rev:1;)
alert http any any -> $HOME_NET any (msg:"Mirage feed: path probed by attackers"; flow:established,to_server; \
http.uri; dataset:isset,mirage-paths,type string,load datasets/paths.lst; {THRESHOLD} classtype:misc-activity; \
sid:1900003; rev:1;)
alert http any any -> any any (msg:"Mirage feed: known payload SHA-256"; flow:established; \
filesha256:datasets/sha256.lst; classtype:trojan-activity; sid:1900004; rev:1;)
"""


def _zeek_value(value: str) -> str:
    return value.split("://", 1)[1] if "://" in value else value


def zeek(s: Snapshot) -> bytes:
    rows = []
    for r in s.ips_in("7d"):
        kind = "Intel::ADDR" if network(r["ip"]).version == 4 else "Intel::SUBNET"
        rows.append((r["ip"], kind, f"attacker confidence={r['confidence']}"))
    rows += [(_zeek_value(r["url"]), "Intel::URL", f"{r['kind']} url") for r in s.lists["urls"]]
    rows += [(r["domain"], "Intel::DOMAIN", "payload domain") for r in s.lists["domains"]]
    rows += [(r["sha256"], "Intel::FILE_HASH", "payload sha256") for r in s.lists["hashes"]]
    rows += [(r["value"], "Intel::SOFTWARE", "attacker user-agent") for r in s.lists["user_agents"]]
    body = [ZEEK_HEADER] + ["\t".join((v, k, SOURCE, d, BASE_URL)) for v, k, d in sorted(set(rows))]
    return lines(body)


def _score(confidence) -> int:
    return min(127, max(1, (int(confidence) * 127 + 50) // 100))


def _b64(values) -> list[str]:
    return [base64.b64encode(v.encode()).decode() for v in sorted(set(values))]


def render(s: Snapshot) -> list[Artifact]:
    ips = s.ips_in("7d")
    iprep = [f"{r['ip']},{CATEGORY_ID},{_score(r['confidence'])}" for r in ips]
    v4 = [r["ip"] for r in ips if network(r["ip"]).version == 4]
    sha = sorted({r["sha256"] for r in s.lists["hashes"]})
    paths = _b64(r["value"] for r in s.lists["paths"])
    uas = _b64(r["value"] for r in s.lists["user_agents"])
    zeek_data = zeek(s)
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
        Artifact("latest/suricata/datasets/ips.lst", lines(v4), "suricata-dataset", len(v4), "7d", suri),
        Artifact("latest/suricata/datasets/sha256.lst", lines(sha), "suricata-dataset", len(sha), "30d", suri),
        Artifact("latest/suricata/datasets/paths.lst", lines(paths), "suricata-dataset", len(paths), "7d", suri),
        Artifact("latest/suricata/datasets/uas.lst", lines(uas), "suricata-dataset", len(uas), "7d", suri),
        Artifact("latest/suricata/mirage.rules", RULES.encode(), "suricata-rules", RULES.count("sid:"), None, suri),
    ]
