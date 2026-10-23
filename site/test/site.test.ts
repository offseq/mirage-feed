import { afterEach, describe, expect, it, vi } from "vitest";
import { renderHome, technique } from "../src/home";
import { isValidIp } from "../src/removal";
import { APP_PATH, FONT_400, FONT_600 } from "../src/assets";
import { CSS } from "../src/style";
import { call, fixture, rawServing, setup } from "./harness";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function published(r2: ReturnType<typeof setup>["r2"], generated = "2026-10-24T03:05:00Z") {
  r2.put("feed.json", fixture("feed.json").replace("2026-10-24T03:05:00Z", generated));
  r2.put("stats.json", fixture("stats.json"));
}
const basic = (s: string) => `Basic ${btoa(s)}`;

async function sha256b64(s: string) {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)));
  return btoa(String.fromCharCode(...d));
}

describe("pages", () => {
  it("renders live stats and the file index from feed.json and stats.json", async () => {
    const { env, r2 } = setup();
    vi.spyOn(Date, "now").mockReturnValue(Date.parse("2026-10-24T09:00:00Z"));
    published(r2);
    const res = await call(env, "/");
    const html = await res.text();
    expect(res.status).toBe(200);
    expect(html).toContain('<p class="big">1,052</p>\n<p class="lede">of 8,715 source IPs seen in the last 24 hours are in the feed</p>');
    expect(html).toContain('<th scope="col" class="n">Last 24 h</th><th scope="col" class="n">In the feed</th>');
    expect(html).toContain('<th scope="row">IPv4, 30-day list</th><td class="n dim">-</td><td class="n">3,904</td>');
    expect(html).toContain("Feed lists cover the last 7 days of activity (30 days for <code>ipv4-30d.txt</code>).");
    expect(html).toContain('<abbr title="');
    expect(html).toContain('The gap is what the <a href="https://mirage.offseq.com/?auth=signup&amp;intent=premium&amp;utm_source=feeds&amp;utm_medium=web&amp;utm_campaign=mirage-feed&amp;utm_content=status">full feed</a> holds');
    expect(html).toContain('href="/mirage-feed/latest/ipv4-7d.txt"');
    expect(html).toContain("TLP:CLEAR");
    expect(html).toContain("utm_source=feeds");
    expect(html).toContain("Top 100 passwords, no usernames");
    expect(html).not.toContain("Stale:");
    expect(html.replace(/<script type="application\/ld\+json">[^<]*<\/script>/, "")).not.toMatch(/<script>|<script [^>]*>[^<]/);
  });

  it("shows a stale notice when the snapshot is older than 36 hours", async () => {
    const { env, r2 } = setup();
    vi.spyOn(Date, "now").mockReturnValue(Date.parse("2026-10-26T00:00:00Z"));
    published(r2);
    expect(await (await call(env, "/")).text()).toContain("Stale: this snapshot was built 44 hours ago.");
  });

  it("renders a designed empty state before the first publish", async () => {
    const { env } = setup();
    vi.stubGlobal("fetch", rawServing({}));
    const res = await call(env, "/");
    const html = await res.text();
    expect(res.status).toBe(200);
    expect(html).toContain("No snapshot yet.");
    expect(html).toContain("not published yet");
  });

  it("renders an empty state when GitHub is down and nothing is cached", async () => {
    const { env } = setup();
    vi.stubGlobal("fetch", vi.fn(async () => Promise.reject(new Error("down"))));
    const res = await call(env, "/");
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("No snapshot yet.");
  });

  it("serves a styled 404", async () => {
    const { env } = setup();
    const res = await call(env, "/nope");
    expect(res.status).toBe(404);
    const html = await res.text();
    expect(html).toContain("Not found");
    expect(html).toContain("MIRAGE-FEED(7)");
  });

  it("serves privacy, robots, sitemap and security.txt", async () => {
    const { env } = setup();
    const privacy = await (await call(env, "/privacy")).text();
    expect(privacy).toContain("Article 6(1)(f)");
    expect(privacy).toContain("dvi.gov.lv");
    expect(privacy).toContain("SEQ SIA, registration no. 40203410806");
    expect(privacy).not.toContain('class="ph"');
    expect(privacy).toContain("The 100 most attempted passwords, without usernames.");
    expect(privacy).toContain("the MISP feed carries up to 7 previous daily events");
    expect(await (await call(env, "/robots.txt")).text()).toContain("Sitemap: https://feeds.offseq.com/sitemap.xml");
    expect(await (await call(env, "/sitemap.xml")).text()).toContain("<loc>https://feeds.offseq.com/privacy</loc>");
    vi.spyOn(Date, "now").mockReturnValue(Date.parse("2026-10-24T15:30:00Z"));
    const sec = await (await call(env, "/.well-known/security.txt")).text();
    expect(sec).toContain("Contact: https://cvd.cert.lv/programs/view/101\nContact: mailto:security@offseq.com\n");
    expect(sec).toContain("Expires: 2027-09-24T00:00:00.000Z");
    expect(sec).toContain("Policy: https://cvd.cert.lv/programs/view/101");
    expect(sec).toContain("Preferred-Languages: en, lv");
    expect(sec).toContain("Canonical: https://feeds.offseq.com/.well-known/security.txt");
    const moved = await call(env, "/security.txt");
    expect(moved.status).toBe(301);
    expect(moved.headers.get("location")).toBe("/.well-known/security.txt");
  });

  it("serves the font and script assets", async () => {
    const { env } = setup();
    for (const path of [FONT_400, FONT_600, APP_PATH]) {
      expect(path).toMatch(/\.[0-9a-f]{8}\.(woff2|js)$/);
      const res = await call(env, path);
      expect(res.headers.get("cache-control")).toBe("public, max-age=31536000, immutable");
      expect(res.headers.get("cross-origin-resource-policy")).toBe("same-origin");
    }
    const font = await call(env, FONT_400);
    expect(font.headers.get("content-type")).toBe("font/woff2");
    expect((await font.arrayBuffer()).byteLength).toBeGreaterThan(10_000);
    expect((await call(env, APP_PATH)).headers.get("content-type")).toContain("javascript");
    expect((await call(env, "/app.js")).status).toBe(404);
    const html = await (await call(env, "/privacy")).text();
    expect(html).toContain(`<link rel="preload" href="${FONT_600}" as="font"`);
    expect(html).toContain(`<script src="${APP_PATH}" defer>`);
  });
});

describe("security headers", () => {
  it("sends a strict CSP whose style hash matches the inlined CSS", async () => {
    const { env, r2 } = setup();
    published(r2);
    const res = await call(env, "/");
    const csp = res.headers.get("content-security-policy")!;
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain(`script-src https://feeds.offseq.com${APP_PATH} https://static.cloudflareinsights.com;`);
    expect(csp).not.toContain("'self' https://feeds");
    expect(csp).toContain(`style-src 'sha256-${await sha256b64(CSS)}'`);
    expect(csp).toContain("require-trusted-types-for 'script'; trusted-types 'none'");
    expect(csp).toContain("base-uri 'none'");
    expect(csp).toContain("report-uri https://mirage.offseq.com/_t/csp");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).not.toContain("unsafe-inline");
    expect(csp).not.toContain("challenges.cloudflare.com");
    expect((await res.text()).includes(`<style>${CSS}</style>`)).toBe(true);
    expect(res.headers.get("strict-transport-security")).toBe("max-age=63072000; includeSubDomains; preload");
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect(res.headers.get("referrer-policy")).toBe("strict-origin-when-cross-origin");
    const pp = res.headers.get("permissions-policy")!;
    expect(pp.split(", ")).toHaveLength(21);
    expect(pp).toContain("xr-spatial-tracking=()");
    for (const dropped of ["publickey-credentials-create", "browsing-topics", "local-fonts", "gamepad"]) expect(pp).not.toContain(dropped);
    expect(csp).toContain("script-src https://feeds.offseq.com/app.");
    expect(csp).toContain(".js https://static.cloudflareinsights.com;");
    expect(csp).toContain("connect-src 'self' https://cloudflareinsights.com https://in.ainalytic.net;");
    expect(pp).not.toContain("clipboard-write");
    expect(res.headers.get("cross-origin-opener-policy")).toBe("same-origin");
    expect(res.headers.get("cross-origin-resource-policy")).toBe("same-origin");
    expect(res.headers.get("x-frame-options")).toBe("DENY");
  });

  it("allows Turnstile only on /removal", async () => {
    const { env } = setup();
    const res = await call(env, "/removal");
    const csp = res.headers.get("content-security-policy")!;
    expect(csp).toContain(`script-src https://feeds.offseq.com${APP_PATH} https://static.cloudflareinsights.com https://challenges.cloudflare.com;`);
    expect(csp).toContain("frame-src https://challenges.cloudflare.com");
    expect(csp).not.toContain("trusted-types");
    expect(res.headers.get("content-security-policy-report-only")).toBeNull();
    const html = await res.text();
    expect(html).toContain('data-sitekey="1x00000000000000000000AA"');
    expect(html).toContain("<noscript>");
  });

  it("sandboxes feed files", async () => {
    const { env, r2 } = setup();
    r2.put("latest/ipv4-7d.txt", "192.0.2.1\n");
    const res = await call(env, "/mirage-feed/latest/ipv4-7d.txt");
    expect(res.headers.get("content-security-policy")).toContain("sandbox");
  });
});

describe("shadow mode", () => {
  const shadow = { SHADOW: "1", SHADOW_AUTH: "ops:s3cret-pass" };

  it("challenges requests without credentials", async () => {
    const { env } = setup(shadow);
    const res = await call(env, "/");
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toContain("Basic");
    expect((await call(env, "/mirage-feed/latest/ipv4-7d.txt")).status).toBe(401);
  });

  it("rejects wrong credentials and fails closed without SHADOW_AUTH", async () => {
    expect((await call(setup(shadow).env, "/", { headers: { authorization: basic("ops:wrong") } })).status).toBe(401);
    expect((await call(setup({ SHADOW: "1" }).env, "/", { headers: { authorization: basic("ops:s3cret-pass") } })).status).toBe(401);
  });

  it("serves a noindex preview with the right credentials", async () => {
    const { env, r2 } = setup(shadow);
    published(r2);
    const res = await call(env, "/", { headers: { authorization: basic("ops:s3cret-pass") } });
    const html = await res.text();
    expect(res.status).toBe(200);
    expect(res.headers.get("x-robots-tag")).toBe("noindex, nofollow");
    expect(res.headers.get("cache-control")).toBe("private, no-store");
    expect(html).toContain('<meta name="robots" content="noindex,nofollow">');
    expect(html).toContain('class="preview"');
    expect(html).toContain("<title>[preview] ");
  });

  it("keeps robots.txt public and disallows everything", async () => {
    const { env } = setup(shadow);
    const res = await call(env, "/robots.txt");
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("User-agent: *\nDisallow: /\n");
  });

  it("has no preview marker outside shadow mode", async () => {
    const { env, r2 } = setup();
    published(r2);
    const res = await call(env, "/");
    expect(res.headers.get("x-robots-tag")).toBeNull();
    expect(await res.text()).not.toContain("noindex");
  });
});

describe("removal IP validation", () => {
  it.each(["9.9.9.9", "185.12.64.1", "2a01:4f8::1", "2a01:4f8:1:2::/64", "2600:1f18:abcd::7"])("accepts %s", (ip) =>
    expect(isValidIp(ip)).toBe(true),
  );
  it.each([
    "", "256.1.1.1", "9.9.9", "01.2.3.4", "9.9.9.9/32", "9.9.9.9/24", "9.9.9.9 ", "example.com",
    "0.1.2.3", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.1.1", "172.16.0.1", "192.0.2.1", "192.168.1.1",
    "198.18.0.1", "198.51.100.7", "203.0.113.5", "224.0.0.1", "255.255.255.255",
    "::", "::/0", "::1", "::ffff:8.8.8.8", "::ffff:808:808", "fe80::1", "fc00::1", "ff02::1", "2001:db8::1", "2001:0db8:1::/64",
    "2a01:4f8::/48", "2a01:4f8::1/128", "2a01:4f8:::1", "[2a01:4f8::1]",
  ])("rejects %j", (ip) => expect(isValidIp(ip)).toBe(false));
});

const UPSTREAM = "https://mirage.example/api/feed/removal";
const SITEVERIFY = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

function services(opts: { turnstile?: boolean; upstream?: Response; hostname?: string; action?: string } = {}) {
  return vi.fn(async (input: RequestInfo | URL, _init?: RequestInit) => {
    const url = String(input);
    if (url === SITEVERIFY) return Response.json({ success: opts.turnstile ?? true, hostname: opts.hostname ?? "feeds.offseq.com", action: opts.action ?? "removal" });
    if (url === UPSTREAM) return opts.upstream ?? new Response("{}", { status: 202 });
    return new Response("unexpected", { status: 500 });
  });
}

const valid = { ip: "9.9.9.9", email: "noc@example.org", reason: "This is our office NAT gateway, not an attacker.", website: "", "cf-turnstile-response": "tok" };
const form = (fields: Record<string, string>, headers: Record<string, string> = {}) => ({
  method: "POST",
  body: new URLSearchParams(fields).toString(),
  headers: { "content-type": "application/x-www-form-urlencoded", "cf-connecting-ip": "198.51.100.9", ...headers },
});

describe("removal", () => {
  it("re-renders the form with an error for an invalid IP, without JS", async () => {
    const { env } = setup();
    const fetchMock = services();
    vi.stubGlobal("fetch", fetchMock);
    const res = await call(env, "/removal", form({ ...valid, ip: "10.0.0.1" }));
    expect(res.status).toBe(400);
    const html = await res.text();
    expect(html).toContain("Enter one public IPv4 address");
    expect(html).toMatch(/name="ip"[^>]*value="10.0.0.1" aria-invalid="true"/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("requires a 20 to 2000 character reason and returns JSON field errors", async () => {
    const { env } = setup();
    vi.stubGlobal("fetch", services());
    const short = await call(env, "/removal", form({ ...valid, reason: "mine" }, { accept: "application/json" }));
    expect(short.status).toBe(400);
    expect(await short.json()).toMatchObject({ ok: false, field: "reason" });
    const noEmail = await call(env, "/removal", form({ ...valid, email: "" }, { accept: "application/json" }));
    expect(await noEmail.json()).toMatchObject({ field: "email" });
    const html = await (await call(env, "/removal")).text();
    expect(html).toContain('required minlength="20" maxlength="2000"');
  });

  it("verifies Turnstile, then forwards upstream with the proxy secret and client IP", async () => {
    const { env } = setup();
    const fetchMock = services();
    vi.stubGlobal("fetch", fetchMock);
    const res = await call(env, "/removal", form(valid));
    expect(res.status).toBe(303);
    expect(res.headers.get("location")).toBe("/removal/sent");
    const calls = fetchMock.mock.calls as unknown as [string, RequestInit][];
    expect(calls.map(([u]) => u)).toEqual([SITEVERIFY, UPSTREAM]);
    const verify = new URLSearchParams(calls[0][1].body as URLSearchParams);
    expect(verify.get("secret")).toBe("turnstile-secret");
    expect(verify.get("response")).toBe("tok");
    expect(verify.get("remoteip")).toBe("198.51.100.9");
    const headers = calls[1][1].headers as Record<string, string>;
    expect(headers["x-feed-proxy-secret"]).toBe("proxy-secret");
    expect(headers["x-feed-client-ip"]).toBe("198.51.100.9");
    expect(headers["content-type"]).toBe("application/json");
    expect(JSON.parse(calls[1][1].body as string)).toEqual({ ip: "9.9.9.9", email: "noc@example.org", reason: valid.reason, website: "" });
    expect(await (await call(env, "/removal/sent")).text()).toContain("Request received");
  });

  it("explains the JavaScript requirement when the Turnstile token is missing or invalid", async () => {
    const { env } = setup();
    const fetchMock = services({ turnstile: false });
    vi.stubGlobal("fetch", fetchMock);
    const missing = await call(env, "/removal", form({ ...valid, "cf-turnstile-response": "" }));
    expect(missing.status).toBe(400);
    expect(await missing.text()).toContain("It needs JavaScript; without it, write to abuse@offseq.com.");
    const bad = await call(env, "/removal", form(valid, { accept: "application/json" }));
    expect(((await bad.json()) as { error: string }).error).toContain("anti-abuse check");
    expect((fetchMock.mock.calls as unknown as [string][]).map(([u]) => u)).toEqual([SITEVERIFY]);
  });

  it("surfaces the upstream FastAPI detail message", async () => {
    const { env } = setup();
    vi.stubGlobal("fetch", services({ upstream: Response.json({ detail: "This address is not listed." }, { status: 404 }) }));
    const res = await call(env, "/removal", form(valid, { accept: "application/json" }));
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ ok: false, error: "This address is not listed." });
  });

  it("reports upstream failure and a missing proxy secret", async () => {
    vi.stubGlobal("fetch", services({ upstream: new Response("", { status: 500 }) }));
    const down = await call(setup().env, "/removal", form(valid));
    expect(down.status).toBe(502);
    expect(await down.text()).toContain("abuse@offseq.com");
    expect((await call(setup({ FEED_PROXY_SECRET: undefined }).env, "/removal", form(valid))).status).toBe(502);
  });

  it("drops honeypot submissions silently", async () => {
    const { env } = setup();
    const fetchMock = services();
    vi.stubGlobal("fetch", fetchMock);
    const res = await call(env, "/removal", form({ ...valid, website: "http://spam.example" }));
    expect(res.status).toBe(303);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rate limits per CF-Connecting-IP", async () => {
    const keys: string[] = [];
    const { env } = setup({ REMOVAL_LIMIT: { limit: async ({ key }: { key: string }) => (keys.push(key), { success: false }) } });
    vi.stubGlobal("fetch", services());
    const res = await call(env, "/removal", form(valid, { accept: "application/json" }));
    expect(res.status).toBe(429);
    expect(keys).toEqual(["198.51.100.9"]);
  });

  it("caps the body at 8 KB even without a Content-Length", async () => {
    const { env } = setup();
    vi.stubGlobal("fetch", services());
    const big = new URLSearchParams({ ...valid, reason: "x".repeat(9000) }).toString();
    const stream = new ReadableStream({
      start(c) {
        c.enqueue(new TextEncoder().encode(big));
        c.close();
      },
    });
    const res = await call(env, "/removal", {
      method: "POST",
      body: stream,
      headers: { "content-type": "application/x-www-form-urlencoded" },
      duplex: "half",
    } as RequestInit);
    expect(res.status).toBe(413);
  });

  it("accepts JSON bodies and rejects cross-origin posts", async () => {
    const { env } = setup();
    vi.stubGlobal("fetch", services());
    const ok = await call(env, "/removal", {
      method: "POST",
      body: JSON.stringify({ ...valid, ip: "2a01:4f8:1:2::/64" }),
      headers: { "content-type": "application/json", accept: "application/json" },
    });
    expect(await ok.json()).toMatchObject({ ok: true });
    const cross = await call(env, "/removal", form(valid, { origin: "https://evil.example" }));
    expect(cross.status).toBe(403);
  });
});

describe("status rendering", () => {
  const base = JSON.parse(fixture("stats.json"));
  const home = (stats: unknown) => renderHome(null, stats as never, 0);

  it("never renders a share above 100%", () => {
    const html = home({ ...base, published: { ...base.published, active_24h: 12_000 } });
    expect(html).toContain("in the feed 100.0%");
    expect(html).toContain('width="100.00%"');
    expect(html).toContain('<p class="big">8,715</p>\n<p class="lede">of 8,715');
    for (const [, pct] of html.matchAll(/(\d+(?:\.\d+)?)%/g)) expect(Number(pct)).toBeLessThanOrEqual(100);
  });

  it("hides the bar when active_24h is missing", () => {
    const { active_24h: _drop, ...published } = base.published;
    const html = home({ ...base, published });
    expect(html).not.toContain('class="gap"');
    expect(html).toContain('<p class="big">2,140</p>\n<p class="lede">source IPs in the 7-day feed</p>');
  });

  it("renders a technique id once when the name is missing or repeats it", () => {
    expect(technique("T1657", "T1657")).toBe("T1657");
    expect(technique("T1657")).toBe("T1657");
    expect(technique("T1110", "T1110 Brute Force")).toBe('T1110 <span class="dim">Brute Force</span>');
    expect(home(base)).not.toMatch(/T1110 <span class="dim">T1110/);
  });

  it("sorts every breakdown by value, descending", () => {
    const html = home({ ...base, services: [{ service: "telnet", ips: 3 }, { service: "ssh", ips: 9 }, { service: "smb", ips: 5 }] });
    const order = (ids: string[]) => ids.map((id) => html.indexOf(`<tr><td>${id}`));
    const ssh = order(["ssh", "smb", "telnet"]);
    expect(ssh).toEqual([...ssh].sort((a, b) => a - b));
    const attack = order(["T1110", "T1190", "T1595", "T1059"]);
    expect(attack.every((i) => i > 0)).toBe(true);
    expect(attack).toEqual([...attack].sort((a, b) => a - b));
  });
});
