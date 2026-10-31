import argparse
import os
import sys
from pathlib import Path

from . import build, check, fetch, netlist, readme, spotlight
from .common import Snapshot, SnapshotError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m generator", description="Mirage community feed generator")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("fetch", help="download and validate the community snapshot")
    p.add_argument("--url", default=os.environ.get("MIRAGE_FEED_URL") or fetch.DEFAULT_URL)
    p.add_argument("--day", help="YYYY-MM-DD; default is the latest build")
    p.add_argument("--out", type=Path, default=Path("snapshot.json"))

    p = sub.add_parser("build", help="render every output format")
    p.add_argument("--snapshot", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--previous", type=Path, help="previous data branch checkout, for MISP history")
    p.add_argument("--allowlist", type=Path, default=netlist.DEFAULT_ALLOWLIST)

    p = sub.add_parser("check", help="safety gates; non-zero exit on any failure")
    p.add_argument("out", type=Path)
    p.add_argument("--previous", type=Path)
    p.add_argument("--allowlist", type=Path, default=netlist.DEFAULT_ALLOWLIST)
    p.add_argument("--allow-delta", action="store_true", help="accept size, churn and concentration anomalies")
    p.add_argument("--bootstrap", action="store_true", help="first publish: no previous data to compare")
    p.add_argument("--allow-rollback", action="store_true", help="accept a snapshot no newer than the previous build")
    p.add_argument("--confirm-with", type=Path, help="build of the previous snapshot day; accept anomalies it shares")
    p.add_argument(
        "--require-leak-rules", action="store_true", help=f"fail when {' and '.join(check.LEAK_ENV)} are empty"
    )

    p = sub.add_parser("readme", help="rewrite the README stats block")
    p.add_argument("--snapshot", type=Path, required=True)
    p.add_argument("--template", type=Path, required=True)
    p.add_argument("--readme", type=Path, required=True)

    p = sub.add_parser("spotlight", help="print weekly release notes as Markdown")
    p.add_argument("--snapshot", type=Path, required=True)

    args = parser.parse_args(argv)
    try:
        if args.cmd == "fetch":
            snap = fetch.fetch(args.url, args.out, args.day)
            print(f"fetched {snap.day}: {len(snap.lists['ips'])} ips -> {args.out}")
        elif args.cmd == "build":
            snap, arts = build.build(args.snapshot, args.out, args.previous, args.allowlist)
            if snap.dropped:
                dropped = ", ".join(f"{k}={n}" for k, n in sorted(snap.dropped.items()))
                print(f"dropped malformed or filtered records: {dropped}", file=sys.stderr)
            print(f"wrote {len(arts)} files to {args.out}")
        elif args.cmd == "check":
            patterns, literals = ([v for v in os.environ.get(k, "").splitlines() if v.strip()] for k in check.LEAK_ENV)
            overridden = check.sustained(args.out, args.previous, args.confirm_with) if args.confirm_with else {}
            for msg in overridden.values():
                print(f"::warning::anomaly gate overridden, the shift held for two snapshot days: {msg}")
            errors = check.run(
                args.out,
                args.previous,
                args.allowlist,
                allow_delta=args.allow_delta or bool(overridden),
                bootstrap=args.bootstrap,
                allow_rollback=args.allow_rollback,
                leak_patterns=patterns,
                leak_literals=literals,
                require_leak_rules=args.require_leak_rules,
            )
            for err in errors:
                print(f"FAIL {err}", file=sys.stderr)
            if errors:
                print(f"{len(errors)} gate failure(s); refusing to publish", file=sys.stderr)
                return 1
            print("all gates passed")
        elif args.cmd == "readme":
            changed = readme.write(args.snapshot, args.template, args.readme)
            print(f"{args.readme}: {'updated' if changed else 'unchanged'}")
        elif args.cmd == "spotlight":
            sys.stdout.write(spotlight.notes(Snapshot.load(args.snapshot)))
    except (SnapshotError, fetch.FetchError, FileExistsError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
