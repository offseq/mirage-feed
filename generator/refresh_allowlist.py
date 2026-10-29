"""Rebuild allowlist.txt and benign-domains.txt from pinned and first-party sources.

Run by hand (`python -m generator.refresh_allowlist`), review the diff, commit. Never runs in CI.
"""

import ipaddress
import json
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
WARNINGLISTS_COMMIT = "fe7651f9f9723fda977cc90d07a2cdcb535909aa"
WARNINGLISTS = f"https://raw.githubusercontent.com/MISP/misp-warninglists/{WARNINGLISTS_COMMIT}/lists/{{}}/list.json"
# First-party service ranges only; customer clouds (AWS, Azure, GCP, Linode) are where attackers live.
IP_LISTS = (
    "rfc1918", "rfc5735", "rfc6598", "rfc3849", "multicast", "ipv6-linklocal", "public-dns-v4", "public-dns-v6",
    "cloudflare", "akamai", "fastly", "apple", "apple-ipv4", "apple-ipv6", "microsoft-office365-ip",
    "microsoft-office365-cn",
)  # fmt: skip
# Akamai's BGP-derived list includes Linode, a customer cloud.
SUBTRACT = {"akamai": "linode"}
GITHUB_META = "https://api.github.com/meta"
GITHUB_KEYS = ("hooks", "web", "api", "git", "pages")
GOOGLE_ALL = "https://www.gstatic.com/ipranges/goog.json"
GOOGLE_CLOUD = "https://www.gstatic.com/ipranges/cloud.json"
# Search, SEO and AI crawler ranges; several sit inside customer clouds, so they are added after the subtraction.
CRAWLERS = (
    "https://developers.google.com/static/crawling/ipranges/common-crawlers.json",
    "https://developers.google.com/static/crawling/ipranges/special-crawlers.json",
    "https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers.json",
    "https://www.bing.com/toolbox/bingbot.json",
    "https://openai.com/gptbot.json",
    "https://openai.com/searchbot.json",
    "https://openai.com/chatgpt-user.json",
    "https://search.developer.apple.com/applebot.json",
    "https://duckduckgo.com/duckduckbot.json",
    "https://api.ahrefs.com/v3/public/crawler-ip-ranges",
)
STATIC = {
    "IANA special-purpose registries (RFC 6890)": (
        "0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 "
        "192.88.99.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4 "
        "::/128 ::1/128 ::ffff:0:0/96 64:ff9b::/96 64:ff9b:1::/48 100::/64 2001::/23 2001:db8::/32 2002::/16 "
        "3fff::/20 fc00::/7 fe80::/10 ff00::/8"
    ),
    "Root servers (https://root-servers.org)": (
        "198.41.0.4 170.247.170.2 192.33.4.12 199.7.91.13 192.203.230.10 192.5.5.241 192.112.36.4 198.97.190.53 "
        "192.36.148.17 192.58.128.30 193.0.14.129 199.7.83.42 202.12.27.33 2001:503:ba3e::2:30 2801:1b8:10::b "
        "2001:500:2::c 2001:500:2d::d 2001:500:a8::e 2001:500:2f::f 2001:500:12::d0d 2001:500:1::53 "
        "2001:7fe::53 2001:503:c27::2:30 2001:7fd::1 2001:500:9f::42 2001:dc3::35"
    ),
    "Microsoft global edge AS8068 (Front Door, Microsoft 365)": "13.107.0.0/16",
    "SemrushBot (https://www.semrush.com/bot/), no machine-readable list": "85.208.96.0/24 185.191.171.0/24",
}
# Security vendors whose own sites show up as "payload" hosts when their scanners fetch them.
SECURITY_VENDORS = ["pentest-tools.com", "shodan.io", "censys.io", "leakix.net", "shadowserver.org", "rapid7.com"]
SHARED_HOSTING = [
    "github.com",
    "githubusercontent.com",
    "github.io",
    "gitlab.com",
    "gitlab.io",
    "bitbucket.org",
    "pastebin.com",
    "transfer.sh",
    "discord.com",
    "discordapp.com",
    "discordapp.net",
    "dropbox.com",
    "dropboxusercontent.com",
    "drive.google.com",
    "docs.google.com",
    "googleusercontent.com",
    "googleapis.com",
    "onedrive.live.com",
    "1drv.ms",
    "sharepoint.com",
    "amazonaws.com",
    "cloudfront.net",
    "azureedge.net",
    "azurewebsites.net",
    "windows.net",
    "herokuapp.com",
    "netlify.app",
    "vercel.app",
    "pages.dev",
    "workers.dev",
    "r2.dev",
    "firebaseapp.com",
    "web.app",
    "appspot.com",
    "ngrok.io",
    "ngrok-free.app",
    "ngrok.app",
    "trycloudflare.com",
    "telegram.org",
    "t.me",
    "mega.nz",
    "mediafire.com",
    "file.io",
    "catbox.moe",
    "gofile.io",
    "bit.ly",
    "tinyurl.com",
]


def _get(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "mirage-feed-allowlist/1 (+https://feeds.offseq.com)"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.load(resp)


def _nets(values) -> list:
    return [ipaddress.ip_network(v.strip(), strict=False) for v in values]


def _subtract(nets: list, remove: list) -> list:
    out = []
    for net in nets:
        parts = [net]
        for r in remove:
            kept = []
            for p in parts:
                if p.version != r.version or not p.overlaps(r):
                    kept.append(p)
                elif not p.subnet_of(r):
                    kept.extend(p.address_exclude(r))
            parts = kept
        out += parts
    return out


def _google(url: str) -> list:
    return _nets(p.get("ipv4Prefix") or p.get("ipv6Prefix") for p in _get(url)["prefixes"])


def _collapse(nets) -> list[str]:
    return [str(n) for v in (4, 6) for n in ipaddress.collapse_addresses(n for n in nets if n.version == v)]


def main() -> None:
    nets = [n for text in STATIC.values() for n in _nets(text.split())]
    for name in IP_LISTS:
        listed = _nets(_get(WARNINGLISTS.format(name))["list"])
        if name in SUBTRACT:
            listed = _subtract(listed, _nets(_get(WARNINGLISTS.format(SUBTRACT[name]))["list"]))
        nets += listed
    meta = _get(GITHUB_META)
    nets += _nets(v for key in GITHUB_KEYS for v in meta[key])
    nets += _subtract(_google(GOOGLE_ALL), _google(GOOGLE_CLOUD))
    nets += [n for url in CRAWLERS for n in _google(url)]
    stamp = datetime.now(UTC).strftime("%Y-%m-%d")
    header = [
        "# Ranges that must never appear in the feed. Generated by generator/refresh_allowlist.py; do not edit.",
        f"# misp-warninglists@{WARNINGLISTS_COMMIT}: {', '.join(IP_LISTS)}; akamai minus linode",
        f"# {GITHUB_META} ({', '.join(GITHUB_KEYS)}), {GOOGLE_ALL} minus {GOOGLE_CLOUD}, retrieved {stamp}",
        *(f"# crawler ranges: {url}" for url in CRAWLERS),
        *(f"# static: {label}" for label in STATIC),
    ]
    (HERE / "allowlist.txt").write_text("\n".join(header + _collapse(nets)) + "\n", encoding="utf-8")
    tranco = _get(WARNINGLISTS.format("tranco10k"))["list"]
    domains = sorted({d.strip().lower().rstrip(".") for d in tranco + SHARED_HOSTING + SECURITY_VENDORS if d.strip()})
    header = [
        "# Domains (and their subdomains) never published in domains-7d.txt; they may still appear inside URLs.",
        f"# misp-warninglists@{WARNINGLISTS_COMMIT}: tranco10k, shared hosting, file drops, security vendors.",
    ]
    (HERE / "benign-domains.txt").write_text("\n".join(header + domains) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
