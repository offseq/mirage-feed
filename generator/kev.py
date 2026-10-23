from functools import cache
from pathlib import Path

KEV_FILE = Path(__file__).resolve().parent / "kev.txt"


@cache
def catalog() -> frozenset[str]:
    lines = KEV_FILE.read_text(encoding="utf-8").splitlines()
    return frozenset(line.strip() for line in lines if line.strip() and not line.startswith("#"))
