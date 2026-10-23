import bisect
import ipaddress
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_ALLOWLIST = HERE / "allowlist.txt"
CANARY = HERE / "canary.txt"


class Allowlist:
    def __init__(self, path: Path):
        nets = []
        for raw in path.read_text(encoding="utf-8").splitlines():
            entry = raw.split("#", 1)[0].strip()
            if entry:
                nets.append(ipaddress.ip_network(entry, strict=True))
        self.ranges = {}
        for version in (4, 6):
            merged = ipaddress.collapse_addresses(n for n in nets if n.version == version)
            spans = [(int(n.network_address), int(n.broadcast_address), str(n)) for n in merged]
            self.ranges[version] = ([s[0] for s in spans], spans)

    def hit(self, net) -> str | None:
        starts, spans = self.ranges[net.version]
        i = bisect.bisect_right(starts, int(net.broadcast_address)) - 1
        if i >= 0 and spans[i][1] >= int(net.network_address):
            return spans[i][2]
        return None
