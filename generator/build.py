import hashlib
from pathlib import Path

from . import (
    LICENSE_CODE,
    LICENSE_DATA,
    MIRRORS,
    NAME,
    PUBLISHER,
    SCHEMA_VERSION,
    TLP,
    firewall,
    history,
    lists,
    lookup,
    misp,
    nsm,
    og,
    stix,
    tables,
)
from .common import Artifact, Snapshot, dumps
from .netlist import DEFAULT_ALLOWLIST, Allowlist

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_FILE = ROOT / "schema" / "record.schema.json"
LICENSE_FILE = ROOT / "LICENSE-DATA"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sums(arts: list[Artifact]) -> str:
    return "".join(f"{_sha256(a.data)}  {a.path}\n" for a in sorted(arts, key=lambda a: a.path))


def _shards(arts: list[Artifact]) -> dict:
    """One entry for all lookup shards; its sha256 is over their SHA256SUMS lines, each shard is listed there."""
    return {
        "path": lookup.DIR,
        "format": "ip-lookup-shards",
        "window": "30d",
        "count": sum(a.count for a in arts),
        "files": len(arts),
        "bytes": sum(len(a.data) for a in arts),
        "sha256": _sha256(_sums(arts).encode()),
        "consumers": ["feeds.offseq.com"],
    }


def feed_index(s: Snapshot, arts: list[Artifact]) -> dict:
    shards = [a for a in arts if a.format == lookup.FORMAT]
    files = [
        {
            "path": a.path,
            "format": a.format,
            "window": a.window,
            "count": a.count,
            "bytes": len(a.data),
            "sha256": _sha256(a.data),
            "consumers": list(a.consumers),
        }
        for a in arts
        if a.format != lookup.FORMAT
    ]
    if shards:
        files.append(_shards(shards))
    return {
        "name": NAME,
        "schema_version": SCHEMA_VERSION,
        "publisher": PUBLISHER,
        "license": {"data": LICENSE_DATA, "code": LICENSE_CODE},
        "tlp": TLP,
        "generated": s.generated,
        "day": s.day,
        "policy": s.policy,
        "stats": s.stats,
        "mirrors": list(MIRRORS),
        "files": sorted(files, key=lambda f: f["path"]),
    }


def artifacts(s: Snapshot, prev: Path | None = None, allow: Allowlist | None = None) -> list[Artifact]:
    arts = [
        *lists.render(s, prev),
        *tables.render(s),
        *stix.render(s, prev),
        *misp.render(s, prev, allow),
        *nsm.render(s),
        *firewall.render(s),
        *og.render(s),
    ]
    arts += lookup.render(s, arts)
    counts = {a.path: a.count for a in arts}
    arts.append(history.render(s, prev, counts["latest/ipv4-added-1d.txt"], counts["latest/ipv4-removed-1d.txt"]))
    arts.append(
        Artifact("schema/record.schema.json", SCHEMA_FILE.read_bytes(), "json-schema", 1, None, ("jsonschema",))
    )
    arts.append(Artifact("LICENSE-DATA", LICENSE_FILE.read_bytes(), "text", 1, None, ()))
    arts.append(Artifact("stats.json", dumps(s.stats, indent=2), "json", 1, None, ("feeds.offseq.com",)))
    arts.append(
        Artifact("feed.json", dumps(feed_index(s, arts), indent=2), "json", len(arts), None, ("feeds.offseq.com",))
    )
    # feed.json lists every other file's hash but not SHA256SUMS', so signing it here is not circular.
    arts.append(Artifact("SHA256SUMS", _sums(arts).encode(), "sha256sums", len(arts), None, ("sha256sum", "minisign")))
    return arts


def build(
    snapshot: Path, out: Path, prev: Path | None = None, allowlist: Path = DEFAULT_ALLOWLIST
) -> tuple[Snapshot, list[Artifact]]:
    if out.exists() and any(out.iterdir()):
        raise FileExistsError(f"{out} is not empty")
    s = Snapshot.load(snapshot)
    arts = artifacts(s, prev, Allowlist(allowlist))
    for a in arts:
        target = out / a.path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(a.data)
    return s, arts
