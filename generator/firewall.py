from .common import ANONYMIZER_TAGS, Artifact, Snapshot, csv_bytes, expiry, lines

CHAINS = ("input", "forward")
DEFENDER_TOP = 500
# Defender raises tenant-wide alerts: shared egress stays out, and so does recon with nothing worse behind it.
DEFENDER_SKIP_TAGS = ANONYMIZER_TAGS
RECON_ONLY_TAGS = frozenset({"web-scan"})
DEFENDER_COLS = (
    "IndicatorType",
    "IndicatorValue",
    "ExpirationTime",
    "Action",
    "Severity",
    "Title",
    "Description",
    "RecommendedActions",
    "RbacGroups",
    "Category",
    "MitreTechniques",
    "GenerateAlert",
)


def mikrotik(v4: list[str], v6: list[str]) -> bytes:
    def section(header: str, ips: list[str]) -> list[str]:
        add = (
            ":do {{ add list=mirage-feed address={0} timeout=7d comment=mirage-feed }} "
            "on-error={{ set [find list=mirage-feed address={0}] timeout=7d }}"
        )
        return [header] + [add.format(ip) for ip in ips] if ips else []

    return lines(section("/ip firewall address-list", v4) + section("/ipv6 firewall address-list", v6))


def nft(v4: list[str], v6: list[str]) -> bytes:
    out = [
        "table inet mirage_feed {",
        "\tset bad4 {",
        "\t\ttype ipv4_addr",
        "\t\tflags interval",
        "\t\tauto-merge",
        "\t}",
        "\tset bad6 {",
        "\t\ttype ipv6_addr",
        "\t\tflags interval",
        "\t\tauto-merge",
        "\t}",
        *(f"\tchain {c} {{\n\t\ttype filter hook {c} priority filter - 10; policy accept;\n\t}}" for c in CHAINS),
        "}",
        *(f"flush chain inet mirage_feed {c}" for c in CHAINS),
        "flush set inet mirage_feed bad4",
        "flush set inet mirage_feed bad6",
        *(
            f"add rule inet mirage_feed {c} {fam} saddr @{name} drop"
            for c in CHAINS
            for fam, name in (("ip", "bad4"), ("ip6", "bad6"))
        ),
    ]
    for name, ips in (("bad4", v4), ("bad6", v6)):
        if ips:
            out.append(f"add element inet mirage_feed {name} {{ " + ", ".join(ips) + " }")
    return lines(out)


def ipset(v4: list[str], v6: list[str]) -> bytes:
    out = []
    for name, family, ips in (("mirage4", "inet", v4), ("mirage6", "inet6", v6)):
        maxelem = max(65536, 1 << (len(ips) - 1).bit_length())
        spec = f"hash:net family {family} hashsize 1024 maxelem {maxelem}"
        out += [f"create {name} {spec} -exist", f"create {name}-tmp {spec} -exist", f"flush {name}-tmp"]
        out += [f"add {name}-tmp {ip}" for ip in ips]
        out += [f"swap {name}-tmp {name}", f"destroy {name}-tmp"]
    return lines(out)


def crowdsec(recs: list[dict]) -> list[list]:
    return [["168h", "Range" if "/" in r["ip"] else "Ip", r["ip"], "mirage-feed"] for r in recs]


def _severity(confidence: int) -> str:
    return "High" if confidence >= 90 else "Medium" if confidence >= 70 else "Low"


def defender(recs: list[dict]) -> list[list]:
    rows = []
    for r in recs:
        severity = _severity(int(r["confidence"]))
        tags = ", ".join(r.get("tags", [])) or "attacker"
        desc = (
            f"Attacked {r['sensors']} OffSeq Mirage honeypots in {r['networks']} networks "
            f"({tags}); confidence {r['confidence']}."
        )
        rows.append(
            [
                "IpAddress",
                r["ip"],
                expiry(r["last_seen"]).strftime("%Y-%m-%dT%H:%M:%S.0Z"),
                "Block",
                severity,
                "Mirage feed: known attacker",
                desc,
                "Block inbound connections from this address.",
                "",
                "SuspiciousActivity",
                (r.get("attack") or [""])[0],
                str(severity != "Low"),
            ]
        )
    return rows


def render(s: Snapshot) -> list[Artifact]:
    recs = s.blockable("7d")
    v4 = [r["ip"] for r in recs if "/" not in r["ip"]]
    v6 = [r["ip"] for r in recs if "/" in r["ip"]]
    n = len(recs)
    cs = crowdsec(recs)
    top = defender(s.ranked_v4(DEFENDER_TOP, DEFENDER_SKIP_TAGS, RECON_ONLY_TAGS))
    return [
        Artifact("latest/mikrotik/mirage-7d.rsc", mikrotik(v4, v6), "routeros-script", n, "7d", ("mikrotik",)),
        Artifact("latest/nft/mirage.nft", nft(v4, v6), "nftables", n, "7d", ("nftables",)),
        Artifact("latest/ipset/mirage.ipset", ipset(v4, v6), "ipset-restore", n, "7d", ("ipset", "iptables")),
        Artifact(
            "latest/crowdsec/mirage-7d.csv",
            csv_bytes(("duration", "scope", "value", "reason"), cs),
            "crowdsec-csv",
            len(cs),
            "7d",
            ("crowdsec",),
        ),
        Artifact(
            f"latest/defender/defender-top{DEFENDER_TOP}.csv",
            csv_bytes(DEFENDER_COLS, top),
            "defender-csv",
            len(top),
            "7d",
            ("defender-for-endpoint",),
        ),
    ]
