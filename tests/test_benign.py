import pytest

from generator.benign import distinctive_path, domain_ok, path_ok, user_agent_ok


@pytest.mark.parametrize(
    ("domain", "ok"),
    [
        ("evil-payload.example", True),
        ("cdn.evil-payload.example", True),
        ("com", False),
        ("co.uk", False),
        ("github.com", False),
        ("raw.githubusercontent.com", False),
        ("localhost", False),
        ("bad_label.example", False),
    ],
)
def test_domain_ok(domain, ok):
    assert domain_ok(domain) is ok


@pytest.mark.parametrize(
    ("path", "ok"),
    [
        ("/.env", True),
        ("/cgi-bin/luci/;stok=/locale", True),
        ("/@vite/env", True),
        ("/p/u/getAuthenticationRequirements.do", True),
        ("/wp-sitemap-users-1.xml", True),
        ("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", True),
        ("/", False),
        ("/favicon.ico", False),
        ("/.well-known/security.txt", False),
        ("/a", False),
        ("/s/33e27393e2431313e2838313/_/;/META-INF/maven/pom.properties", False),
        ("/x/0123456789abcdef0123", False),
        ("/q/dGhpc2lzYXRva2VuMTIzNDU2", False),
        ("/user@example.php", False),
        ("/@vite/../a@b", False),
        ("/login", False),
        ("/Login/", False),
        ("//admin", False),
        ("/api/graphql", False),
        ("/mcp/", False),
        ("/wp-admin/admin-ajax.php", False),
        ("/logon/LogonPoint/index.html", False),
        ("/v1/models", False),
    ],
)
def test_path_ok(path, ok):
    assert path_ok(path) is ok


@pytest.mark.parametrize(
    ("path", "cves", "distinctive"),
    [
        ("/.env", [], False),
        ("/.git/config", [], False),
        ("/ecp/Current/exporttool/x.application", ["CVE-2021-26855"], True),
        ("/cgi-bin/.%2e/.%2e/bin/sh", [], True),
        ("/..;/env.js", [], True),
        ("/index.php?s=${jndi:ldap://x}", [], True),
        ("/x.php?cmd=id;uname", [], True),
        ("/HNAP1/", [], True),
        ("/boaform/admin/formLogin", [], True),
        ("/setup.cgi?next_file=netgear.cfg", [], True),
        ("/invoker/readonly", [], True),
        ("/../../etc/passwd", [], True),
    ],
)
def test_distinctive_path(path, cves, distinctive):
    assert distinctive_path(path, cves) is distinctive


@pytest.mark.parametrize(
    "ua",
    [
        "gobuster/3.8.2",
        "Mozilla/5.0 zgrab/0.x",
        "friendly-scanner",
        "libredtail-http",
        "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0 Safari/537.36 Nuclei",
        "WebSiphon/next-0.1",
        "=cmd|' /C calc'!A0",
    ],
)
def test_user_agent_kept(ua):
    assert user_agent_ok(ua)


@pytest.mark.parametrize(
    "ua",
    [
        "  ",
        "Mozilla/5.0",
        "Mozilla/5.0 (compatible)",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/5",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0 Safari/537.36 "
        "OPR/95.0.0.0 (Edition Yx 05)",
        "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/1",
        "Mozilla/5.0 (Linux; U; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/112.0 Mobile "
        "Safari/537.36 XiaoMi/MiuiBrowser/14.4.0-g",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0 Electron/2.0 Safari/537.36",
        "curl/7.64.1",
        "python-requests/2.32.5",
        "Go-http-client/1.1",
        "VLC/3.0.20",
        "Wget/1.21",
        "okhttp/4.12.0",
        "axios/1.7.2",
        "node-fetch/1.0",
        "Java/1.8.0_181",
        "libwww-perl/6.72",
        "CCBot/2.0 (https://commoncrawl.org/faq/)",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot",
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot",
        "Mozilla/5.0 (compatible; Meta-ExternalAgent/1.0; +https://developers.facebook.com/docs/sharing/webmasters/crawler)",
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; PerplexityBot/1.0; +https://perplexity.ai/x)",
        "DuckAssistBot/1.1 (https://duckduckgo.com/duckassistbot)",
        "Mozilla/5.0 (compatible; Bravebot/1.0; +https://brave.com/search/)",
        "Mozilla/5.0 (compatible; cohere-ai; +https://cohere.com/crawler)",
        "Mozilla/5.0 (compatible; GrokBot/1.0; +https://x.ai/)",
        "Mozilla/5.0 (compatible; Qwenbot/1.0; +https://qwen.alibaba.com/)",
        "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)",
        "Hello from Palo Alto Networks, find out more about our scans in https://docs-cortex.paloaltonetworks.com/r/1/Cortex-Xpanse",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/140.0.0.0 Safari/537.36 ModatScanner/1.2 (+https://modat.io/)",
        "Mozilla/5.0 (compatible; Infrawatch/1.0; +https://infrawat.ch/)",
        "Mozilla/5.0 (compatible; InternetMeasurement/1.0; +https://internet-measurement.com/)",
        "Mozilla/5.0 (l9scan/2.0.33e27393e2431313e2838313; +https://leakix.net)",
        "Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com) AppleWebKit/537.36",
        "certwatcher-ai/0.1 (authorized passive reconnaissance)",
        "Synthient-Research-Scanner/1.0",
    ],
)
def test_user_agent_dropped(ua):
    assert not user_agent_ok(ua)
