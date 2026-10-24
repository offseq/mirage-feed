import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts/r2-publish.sh"
# Records each call and keeps uploaded objects under $STORE, so list-objects-v2 answers from what was put.
FAKE_AWS = r"""#!/usr/bin/env bash
set -euo pipefail
echo "$*" >> "$STORE/calls"
case "$1 $2" in
  "s3 cp") key=${4#s3://*/}; mkdir -p "$STORE/obj/$(dirname "$key")"; cp "$3" "$STORE/obj/$key" ;;
  "s3 rm") key=${3#s3://*/}; rm -rf "$STORE/obj/$key" ;;
  "s3api list-objects-v2")
    cd "$STORE/obj"
    find builds -type f 2> /dev/null | sort | while read -r k; do
      printf '["%s","%s"]\n' "$k" "$(cat "$STORE/mtime/${k#builds/}" 2> /dev/null || echo 2026-10-01T00:00:00Z)"
    done | jq -s . ;;
esac
"""

pytestmark = pytest.mark.skipif(not all(shutil.which(t) for t in ("bash", "jq", "sha256sum")), reason="needs jq")


@pytest.fixture
def env(tmp_path):
    bin_dir, store = tmp_path / "bin", tmp_path / "store"
    bin_dir.mkdir()
    (store / "obj").mkdir(parents=True)
    (bin_dir / "aws").write_text(FAKE_AWS)
    (bin_dir / "aws").chmod(0o755)
    return {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "STORE": str(store),
        "BUCKET": "mirage-feed",
        "R2_ENDPOINT": "https://r2.example",
        "DAY": "2026-10-23",
        "GENERATED": "2026-10-24T03:05:00Z",
    }


def publish(env, out: Path, step: str):
    subprocess.run(["bash", str(SCRIPT), step, str(out)], env=env, check=True)


def calls(env) -> list[str]:
    return (Path(env["STORE"]) / "calls").read_text().splitlines()


def build_tree(root: Path, tag: str) -> str:
    (root / "latest").mkdir(parents=True)
    (root / "latest/ipv4-7d.txt").write_text(f"{tag}\n")
    (root / "feed.json").write_text("{}\n")
    (root / "SHA256SUMS").write_text(f"{tag}  latest/ipv4-7d.txt\n")
    return hashlib.sha256((root / "SHA256SUMS").read_bytes()).hexdigest()


def test_files_land_under_the_build_before_the_pointer_moves(tmp_path, env):
    sums = build_tree(tmp_path / "out", "a")
    version = sums[:16]
    publish(env, tmp_path / "out", "upload")
    puts = [c.split()[3] for c in calls(env)]
    assert sorted(puts) == [
        f"s3://mirage-feed/builds/{version}/{p}" for p in ("SHA256SUMS", "feed.json", "latest/ipv4-7d.txt")
    ]
    assert not (Path(env["STORE"]) / "obj/_meta").exists()
    publish(env, tmp_path / "out", "flip")
    meta = json.loads((Path(env["STORE"]) / "obj/_meta/published.json").read_text())
    assert meta == {"generated": "2026-10-24T03:05:00Z", "day": "2026-10-23", "sha256sums": sums, "version": version}
    assert all("--endpoint-url https://r2.example" in c for c in calls(env))


def test_flip_keeps_the_three_newest_builds_and_the_current(tmp_path, env):
    store = Path(env["STORE"])
    versions = []
    for i, tag in enumerate("abcde"):
        out = tmp_path / tag
        versions.append(build_tree(out, tag)[:16])
        publish(env, out, "upload")
        (store / "mtime" / versions[-1] / "latest").mkdir(parents=True)
        for rel in ("SHA256SUMS", "feed.json", "latest/ipv4-7d.txt"):
            (store / "mtime" / versions[-1] / rel).write_text(f"2026-10-2{i}T03:00:00Z")
    publish(env, tmp_path / "b", "flip")
    left = sorted(p.name for p in (store / "obj/builds").iterdir())
    assert left == sorted(versions[1:])
    assert json.loads((store / "obj/_meta/published.json").read_text())["version"] == versions[1]
