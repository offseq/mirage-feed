from .common import Artifact, Snapshot, dumps, network
from .tables import IP_FIELDS

DIR = "latest/lookup/"
FORMAT = "ip-lookup-shard"
LISTS = (
    "ipv4-1d.txt",
    "ipv4-7d.txt",
    "ipv4-30d.txt",
    "ipv4-top1k.txt",
    "ipv4-top10k.txt",
    "ipv6-7d.txt",
    "anonymizers-7d.txt",
    "known-scanners-ipv4.txt",
    "known-scanners-ipv6.txt",
)
FIELDS = tuple(f for f in IP_FIELDS if f != "window")


def shard(value: str) -> str:
    net = network(value)
    if net.version == 4:
        return f"{DIR}v4/{int(net.network_address) >> 24}.json"
    return f"{DIR}v6/{int(net.network_address) >> 112:x}.json"


def render(s: Snapshot, arts: list[Artifact]) -> list[Artifact]:
    """Per-/8 and per-first-hextet slices of every IP list, so /ip reads one small file."""
    data = {a.path: a.data for a in arts}
    entries: dict[str, dict] = {}
    for name in LISTS:
        for value in data[f"latest/{name}"].decode().split():
            entries.setdefault(value, {"lists": []})["lists"].append(name)
    for r in s.ips_in("7d"):
        if r["ip"] in entries:
            entries[r["ip"]]["record"] = {k: r[k] for k in FIELDS if k in r}
    shards: dict[str, dict] = {}
    for value, entry in entries.items():
        shards.setdefault(shard(value), {})[value] = entry
    return [
        Artifact(path, dumps(body), FORMAT, len(body), "30d", ("feeds.offseq.com",))
        for path, body in sorted(shards.items())
    ]
