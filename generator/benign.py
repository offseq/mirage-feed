"""Filters that keep widely shared, benign values out of the non-IP lists."""

import re
from functools import cache
from pathlib import Path

BENIGN_DOMAINS = Path(__file__).resolve().parent / "benign-domains.txt"
LABEL = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)")
TLD = re.compile(r"[a-z]{2,63}|xn--[a-z0-9-]{1,59}")
PUBLIC_SUFFIXES = frozenset(
    [
        "com",
        "net",
        "org",
        "info",
        "biz",
        "io",
        "co",
        "me",
        "tv",
        "cc",
        "ws",
        "su",
        "xyz",
        "top",
        "online",
        "site",
        "club",
        "shop",
        "store",
        "app",
        "dev",
        "cloud",
        "uk",
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "de",
        "fr",
        "nl",
        "ru",
        "cn",
        "jp",
        "br",
        "in",
        "au",
        "com.au",
        "net.au",
        "co.jp",
        "ne.jp",
        "com.br",
        "com.cn",
        "net.cn",
        "org.cn",
        "eu",
        "us",
        "ca",
        "it",
        "es",
        "pl",
        "ch",
        "se",
        "no",
        "fi",
        "dk",
        "be",
        "at",
        "cz",
        "sk",
        "hu",
        "ro",
        "bg",
        "gr",
        "pt",
        "ie",
        "lv",
        "lt",
        "ee",
        "ua",
        "by",
        "kz",
        "tr",
        "com.tr",
        "ir",
        "vn",
        "com.vn",
        "id",
        "co.id",
        "my",
        "com.my",
        "sg",
        "com.sg",
        "hk",
        "com.hk",
        "tw",
        "com.tw",
        "kr",
        "co.kr",
        "th",
        "co.th",
        "ph",
        "com.ph",
        "pk",
        "bd",
        "ng",
        "za",
        "co.za",
        "mx",
        "com.mx",
        "ar",
        "com.ar",
        "cl",
        "pe",
        "tk",
        "ml",
        "ga",
        "cf",
        "gq",
    ]
)
DENY_PATHS = frozenset({"/", "/favicon.ico", "/robots.txt", "/sitemap.xml", "/index.html"})
# Self-identifying search and archive crawlers fetch everything; listing them as attackers is a false positive.
CRAWLER_UA = re.compile(
    r"\b(CCBot|Googlebot|bingbot|Applebot|YandexBot|DuckDuckBot|Baiduspider|AhrefsBot|SemrushBot|MJ12bot|DotBot"
    r"|PetalBot|facebookexternalhit|GPTBot|ClaudeBot|Amazonbot|Bytespider|archive\.org_bot|ia_archiver)\b",
    re.I,
)
BROWSER_UA = re.compile(r"^Mozilla/5\.0 .*\b(Chrome|Firefox|Safari|Edg)/")
TOOL_UA = re.compile(
    r"bot|crawl|spider|scan|curl|wget|python|go-http|zgrab|masscan|nmap|nikto|sqlmap|nuclei|gobuster|dirbuster|"
    r"ffuf|httpx|java/|libwww|okhttp|axios|node-fetch|headless|phantom|selenium",
    re.I,
)


@cache
def _benign_domains() -> frozenset[str]:
    lines = BENIGN_DOMAINS.read_text(encoding="utf-8").splitlines()
    return frozenset(line.strip() for line in lines if line.strip() and not line.startswith("#"))


def _suffixes(domain: str):
    labels = domain.split(".")
    return (".".join(labels[i:]) for i in range(len(labels)))


def domain_ok(domain: str) -> bool:
    labels = domain.split(".")
    if len(domain) > 253 or len(labels) < 2 or not all(LABEL.fullmatch(lb) for lb in labels):
        return False
    if not TLD.fullmatch(labels[-1]) or domain in PUBLIC_SUFFIXES:
        return False
    deny = _benign_domains()
    return not any(s in deny for s in _suffixes(domain))


def path_ok(path: str) -> bool:
    return len(path) >= 3 and path not in DENY_PATHS and not path.startswith("/.well-known/")


def user_agent_ok(ua: str) -> bool:
    if not ua.strip() or CRAWLER_UA.search(ua):
        return False
    return not (BROWSER_UA.search(ua) and not TOOL_UA.search(ua))
