"""Filters that keep widely shared, benign values out of the non-IP lists."""

import re
from functools import cache
from pathlib import Path
from urllib.parse import urlsplit

BENIGN_DOMAINS = Path(__file__).resolve().parent / "benign-domains.txt"
LABEL = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)")
TLD = re.compile(r"[a-z]{2,63}|xn--[a-z0-9-]{1,59}")
URL = re.compile(r"[a-z][a-z0-9+.-]*://\S+")
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
DENY_PATHS = frozenset(
    {
        "/",
        "/favicon.ico",
        "/robots.txt",
        "/sitemap.xml",
        "/sitemap_index.xml",
        "/index.html",
        "/index.php",
        "/ads.txt",
        "/security.txt",
        "/login",
        "/signin",
        "/sign-in",
        "/logout",
        "/admin",
        "/admin/login",
        "/auth",
        "/auth/login",
        "/user/login",
        "/users/login",
        "/account/login",
        "/password/reset",
        "/api",
        "/graphql",
        "/health",
        "/about",
        "/contact",
        "/careers",
        "/checkout",
        "/privacy",
        "/register",
        "/signup",
        "/docs",
        "/feed",
        "/services",
        "/portal",
        "/wp-login.php",
        "/wp-admin",
        "/wp-admin/admin-ajax.php",
        "/wp-json",
        "/xmlrpc.php",
        "/autodiscover/autodiscover.json",
        "/remote/login",
        "/logon/logonpoint/index.html",
        "/vpn/index.html",
        "/actuator/health",
        "/assets/js/app.min.js",
        "/assets/css/app.min.css",
        "/mcp",
        "/sse",
        "/v1/models",
    }
)
# Pages of the AI decoy sites themselves, reached by crawlers following the decoy's own links.
DECOY_PATH = re.compile(r"/(dashboard|account|forgot-password|reset-password|onboarding|members|projects)([/?#]|$)")
# LeakIX encodes the scanned target in /s/<token>/; long hex or base64 runs are per-target tokens too.
TOKEN_PATH = re.compile(
    r"/s/[^/]+/|[0-9a-fA-F]{16,}|(?=[A-Za-z0-9+=]*[0-9])(?=[A-Za-z0-9+=]*[A-Za-z])[A-Za-z0-9+=]{16,}"
)
EXPLOIT_PATH = re.compile(
    r"\.\.|;|%2e|%%32|\$\{|cgi-bin|/etc/passwd|/bin/sh|invoker/|/HNAP1|boaform|setup\.cgi|GponForm|tmUnblock\.cgi"
    r"|php-cgi|eval-stdin\.php|\.php\?.*[;|`$&<>]",
    re.I,
)
# A tool named here is distinctive even when its UA would otherwise read as a scanner or a library.
ATTACK_TOOL_UA = re.compile(
    r"zgrab|masscan|nmap|nikto|sqlmap|nuclei|gobuster|dirbuster|ffuf|wpscan|hydra|friendly-scanner|sipvicious"
    r"|libredtail|hello,? ?world",
    re.I,
)
SELF_ID_UA = re.compile(
    r"bot|crawl|spider|scan|archiver|fetcher|externalagent|webindexer|inspect|measurement|infrawatch|xpanse"
    r"|research|reconnaissance|authorized|discovery|customuseragent|cohere-ai|https?://|www\.|@",
    re.I,
)
# Real VPN clients: worth hunting on, but an IDS rule on them would fire on every employee login.
VPN_CLIENT_UA = re.compile(
    r"anyconnect|f5 ?access|pulse-?secure|globalprotect|citrixreceiver|fortisslvpn|forticlient|openvpn", re.I
)
LIBRARY_UA = re.compile(
    r"^(curl|wget|python-requests|python-urllib|python-httpx|aiohttp|go-http-client|okhttp|axios|node-fetch|undici"
    r"|java|apache-httpclient|libwww-perl|vlc|ureq|reqwest|postmanruntime)\b",
    re.I,
)
BROWSER_TOKENS = frozenset(
    {"mozilla", "applewebkit", "chrome", "chromium", "safari", "firefox", "gecko", "version", "mobile", "edg", "edga",
     "edge", "opr", "crios", "fxios", "yabrowser", "samsungbrowser", "trident", "vivaldi", "electron", "xiaomi",
     "miuibrowser", "ucbrowser", "huaweibrowser"}
)  # fmt: skip
PARENS = re.compile(r"\([^)]*\)?")


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


def url_ok(url: str) -> bool:
    if not URL.fullmatch(url) or "%U%" in url:
        return False
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    host = (parts.hostname or "").rstrip(".")
    # A listed site's front page is a scanner fetching it, not a payload.
    if parts.path in ("", "/") and not parts.query and TLD.fullmatch(host.rsplit(".", 1)[-1]) and not domain_ok(host):
        return False
    # Per-target query tokens could name the sensor that was attacked.
    return not TOKEN_PATH.search(parts.query)


def _path_key(path: str) -> str:
    key = re.sub(r"/{2,}", "/", path.casefold()).rstrip("/") or "/"
    return key.removeprefix("/api") if key.startswith("/api/") else key


def path_ok(path: str) -> bool:
    key = _path_key(path)
    if len(path) < 3 or path.startswith("/.well-known/") or key in DENY_PATHS:
        return False
    if DECOY_PATH.match(key) and not EXPLOIT_PATH.search(path):
        return False
    if "@" in path.removeprefix("/@vite/"):
        return False
    return not TOKEN_PATH.search(path)


def distinctive_path(path: str, cves) -> bool:
    return bool(cves) or bool(EXPLOIT_PATH.search(path))


def _browser(ua: str) -> bool:
    products = PARENS.sub(" ", ua).split()
    return all(p.split("/", 1)[0].casefold() in BROWSER_TOKENS for p in products)


def user_agent_ok(ua: str) -> bool:
    if not ua.strip():
        return False
    if ATTACK_TOOL_UA.search(ua):
        return True
    return not (SELF_ID_UA.search(ua) or LIBRARY_UA.search(ua) or _browser(ua))
