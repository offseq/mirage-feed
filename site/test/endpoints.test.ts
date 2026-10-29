import { afterEach, describe, expect, it, vi } from "vitest";
import { MINISIGN_PUB, renderAtom } from "../src/meta";
import { limitKey, parseAddr } from "../src/addr";
import { CSS } from "../src/style";
import { call, fixture, setup } from "./harness";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const NOW = Date.parse("2026-10-24T09:00:00Z");

function published(r2: ReturnType<typeof setup>["r2"], generated = "2026-10-24T03:05:00Z") {
  r2.put("feed.json", fixture("feed.json").replace("2026-10-24T03:05:00Z", generated));
  r2.put("stats.json", fixture("stats.json"));
}

const record = (extra: Record<string, unknown> = {}) => ({
  first_seen: "2026-10-20T04:00:00Z",
  last_seen: "2026-10-23T22:00:00Z",
  asn: 64500,
  as_org: "Example Hosting",
  country: "NL",
  services: ["ssh", "telnet"],
  tags: ["bruteforce"],
  attack: ["T1110.001"],
  cves: ["CVE-2024-3400"],
  kev: true,
  sensors: 5,
  networks: 3,
  hits: 812,
  confidence: 88,
  ...extra,
});

const SHARDS: Record<string, Record<string, { lists: string[]; record?: Record<string, unknown> }>> = {
  "v4/9": { "9.9.9.9": { lists: ["ipv4-1d.txt", "ipv4-7d.txt", "ipv4-30d.txt", "ipv4-top1k.txt", "ipv4-top10k.txt"], record: record() } },
  "v4/8": { "8.8.4.4": { lists: ["ipv4-30d.txt"] } },
  "v4/45": { "45.9.0.1": { lists: ["anonymizers-7d.txt"], record: record() } },
  "v4/71": { "71.6.135.131": { lists: ["known-scanners-ipv4.txt"] } },
  "v6/2a01": { "2a01:4f8:1:2::/64": { lists: ["ipv6-7d.txt"], record: record() } },
};

function lookupData(r2: ReturnType<typeof setup>["r2"]) {
  published(r2);
  for (const [name, body] of Object.entries(SHARDS)) r2.put(`latest/lookup/${name}.json`, JSON.stringify(body));
}

describe("removal POST headers", () => {
  const valid = { ip: "9.9.9.9", email: "noc@example.org", reason: "This is our office NAT gateway, not an attacker.", website: "", "cf-turnstile-response": "tok" };
  const post = (fields: Record<string, string>, headers: Record<string, string> = {}) => ({
    method: "POST",
    body: new URLSearchParams(fields).toString(),
    headers: { "content-type": "application/x-www-form-urlencoded", "cf-connecting-ip": "198.51.100.9", ...headers },
  });
  const siteverify = (j: Record<string, unknown>) =>
    vi.fn(async (input: RequestInfo | URL) =>
      String(input).includes("siteverify") ? Response.json({ success: true, hostname: "feeds.offseq.com", action: "removal", ...j }) : new Response("{}", { status: 202 }),
    );

  it("marks every outcome no-store with Vary: Accept", async () => {
    vi.stubGlobal("fetch", siteverify({}));
    const outcomes = [
      await call(setup().env, "/removal", post(valid)),
      await call(setup().env, "/removal", post({ ...valid, ip: "10.0.0.1" })),
      await call(setup().env, "/removal", post(valid, { origin: "https://evil.example" })),
      await call(setup().env, "/removal", post({ ...valid, reason: "x".repeat(9000) })),
      await call(setup().env, "/removal", post(valid, { accept: "application/json" })),
      await call(setup({ REMOVAL_LIMIT: { limit: async () => ({ success: false }) } }).env, "/removal", post(valid)),
    ];
    expect(outcomes.map((r) => r.status)).toEqual([303, 400, 403, 413, 200, 429]);
    for (const r of outcomes) {
      expect(r.headers.get("cache-control")).toBe("no-store");
      expect(r.headers.get("vary")).toBe("Accept");
    }
    expect(outcomes[5].headers.get("retry-after")).toBe("60");
  });

  it("validates before rate limiting and keeps the input on a 429", async () => {
    const limited = setup({ REMOVAL_LIMIT: { limit: async () => ({ success: false }) } }).env;
    expect((await call(limited, "/removal", post({ ...valid, email: "nope" }))).status).toBe(400);
    const html = await (await call(limited, "/removal", post(valid))).text();
    expect(html).toContain('value="9.9.9.9"');
    expect(html).toContain("This is our office NAT gateway");
  });

  it("answers JSON clients with JSON on an oversized body", async () => {
    const res = await call(setup().env, "/removal", post({ ...valid, reason: "x".repeat(9000) }, { accept: "application/json" }));
    expect(res.status).toBe(413);
    expect(await res.json()).toMatchObject({ ok: false });
  });

  it("rejects a Turnstile token issued for another hostname or action", async () => {
    vi.stubGlobal("fetch", siteverify({ hostname: "evil.example" }));
    expect((await call(setup().env, "/removal", post(valid))).status).toBe(400);
    vi.stubGlobal("fetch", siteverify({ action: "login" }));
    expect((await call(setup().env, "/removal", post(valid))).status).toBe(400);
  });

  it("renders a server-side error page that focuses the message and says Error in the title", async () => {
    vi.stubGlobal("fetch", siteverify({}));
    const html = await (await call(setup().env, "/removal", post({ ...valid, email: "nope" }))).text();
    expect(html).toContain("<title>Error: Removal request</title>");
    expect(html).toContain('id="form-msg" role="alert" tabindex="-1" data-msg autofocus>');
    expect(html).toMatch(/id="email"[^>]*aria-invalid="true" aria-describedby="email-hint form-msg"/);
  });
});

describe("removal form", () => {
  it("keeps hints out of labels, wires aria-describedby and sets the Turnstile action", async () => {
    const html = await (await call(setup().env, "/removal")).text();
    expect(html).toContain('<label for="ip">IP address</label>\n<span class="hint" id="ip-hint">');
    expect(html).toMatch(/id="reason"[^>]*aria-describedby="reason-hint"/);
    expect(html).toContain('data-action="removal"');
    expect(html).not.toContain("autofocus");
  });

  it("keeps a prefilled form out of analytics, CSP reports and referrers", async () => {
    const res = await call(setup().env, "/removal?ip=9.9.9.9");
    const csp = res.headers.get("content-security-policy") ?? "";
    expect(res.headers.get("cache-control")).toBe("no-store, no-transform");
    expect(res.headers.get("referrer-policy")).toBe("no-referrer");
    expect(csp).toContain("challenges.cloudflare.com");
    expect(csp).not.toContain("cloudflareinsights");
    expect(csp).not.toContain("report-uri");
    expect(csp).not.toContain("ainalytic");
    const html = await res.text();
    expect(html).toContain('<meta name="robots" content="noindex,nofollow">');
    expect(html).not.toContain('rel="canonical"');
    expect((await call(setup().env, "/removal")).headers.get("content-security-policy")).toContain("report-uri");
  });

  it("prefills the address from ?ip= and escapes it", async () => {
    const env = setup().env;
    expect(await (await call(env, "/removal?ip=9.9.9.9")).text()).toContain('value="9.9.9.9"');
    expect(await (await call(env, `/removal?ip=${encodeURIComponent('"><x')}`)).text()).toContain('value="&quot;&gt;&lt;x"');
  });
});

describe("methods and redirects", () => {
  it.each([
    ["/removal", "GET, HEAD, POST"],
    ["/mirage-feed/latest/ipv4-7d.txt", "GET, HEAD, OPTIONS"],
    ["/", "GET, HEAD"],
  ])("405 on %s lists %s", async (path, allow) => {
    const res = await call(setup().env, path, { method: "PUT" });
    expect(res.status).toBe(405);
    expect(res.headers.get("allow")).toBe(allow);
    expect(res.headers.get("cache-control")).toBe("no-store");
  });

  it.each(["/mirage-feed", "/mirage-feed/", "/mirage-feed/latest/"])("redirects %s to /#files with a relative Location", async (path) => {
    const res = await call(setup().env, path, { headers: { host: "evil.example" } });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/#files");
  });

  it("keeps the MISP directory redirect relative", async () => {
    expect((await call(setup().env, "/mirage-feed/misp/")).headers.get("location")).toBe("/mirage-feed/misp/manifest.json");
  });
});

describe("metadata endpoints", () => {
  it("serves robots and sitemap with an hour of caching and lastmod", async () => {
    const { env, r2 } = setup();
    published(r2);
    const robots = await call(env, "/robots.txt");
    expect(robots.headers.get("cache-control")).toBe("public, max-age=3600");
    const map = await (await call(env, "/sitemap.xml")).text();
    expect(map).toContain("<url><loc>https://feeds.offseq.com/</loc><lastmod>2026-10-24T03:05:00Z</lastmod></url>");
    expect(map).toContain("<url><loc>https://feeds.offseq.com/removal</loc></url>");
    expect(map).toMatch(/<loc>https:\/\/feeds\.offseq\.com\/privacy<\/loc><lastmod>\d{4}-\d\d-\d\d<\/lastmod>/);
    expect(map).not.toContain("/ip");
    expect(map).not.toContain("/removal/sent");
  });

  it("publishes the minisign key in minisign .pub format", async () => {
    expect(MINISIGN_PUB).toBe("untrusted comment: minisign public key A39277F8C2FBBB1E\nRWQeu/vC+HeSo+5whq+ViPiKFUe35GOuuVll6WA6QKlFNirw7IzweToA\n");
    const res = await call(setup().env, "/.well-known/mirage-feed-minisign.pub");
    expect(await res.text()).toBe(MINISIGN_PUB);
  });

  it("serves favicon.ico, apple-touch-icon and og.png with an embedded fallback", async () => {
    const { env } = setup();
    const ico = await call(env, "/favicon.ico");
    expect(ico.headers.get("content-type")).toBe("image/x-icon");
    expect(new Uint8Array(await ico.arrayBuffer()).slice(0, 4)).toEqual(new Uint8Array([0, 0, 1, 0]));
    expect((await call(env, "/apple-touch-icon.png")).headers.get("content-type")).toBe("image/png");
    const fallback = new Uint8Array(await (await call(env, "/og.png")).arrayBuffer());
    expect([...fallback.slice(1, 4)].map((c) => String.fromCharCode(c)).join("")).toBe("PNG");
    expect(fallback.byteLength).toBeLessThanOrEqual(40_000);
    const live = setup();
    live.r2.put("og.png", "fresh-card");
    expect(await (await call(live.env, "/og.png")).text()).toBe("fresh-card");
    const down = setup();
    down.r2.failing = true;
    vi.stubGlobal("fetch", vi.fn(async () => new Response("", { status: 503 })));
    expect((await (await call(down.env, "/og.png")).arrayBuffer()).byteLength).toBe(fallback.byteLength);
  });
});

describe("status and badges", () => {
  it("reports a fresh build with counts", async () => {
    const { env, r2 } = setup();
    vi.spyOn(Date, "now").mockReturnValue(NOW);
    published(r2);
    const res = await call(env, "/status.json");
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(await res.json()).toEqual({
      generated: "2026-10-24T03:05:00Z",
      day: "2026-10-23",
      age_seconds: 21_300,
      stale: false,
      counts: { ips_7d: 2140, active_24h: 1052, scanners: 790, cves: 8 },
    });
    const fresh = await call(env, "/badge/freshness.json");
    expect(fresh.headers.get("cache-control")).toBe("public, max-age=300");
    expect(await fresh.json()).toEqual({ schemaVersion: 1, label: "updated", message: "5 h ago", color: "0b6e8a" });
    expect(await (await call(env, "/badge/ips.json")).json()).toEqual({ schemaVersion: 1, label: "attacker IPs, 7 d", message: "2,140", color: "0b6e8a" });
  });

  it("answers 503 and a red badge after 36 hours, and when nothing is published", async () => {
    const { env, r2 } = setup();
    vi.spyOn(Date, "now").mockReturnValue(Date.parse("2026-10-25T16:00:00Z"));
    published(r2);
    const res = await call(env, "/status.json");
    expect(res.status).toBe(503);
    expect(((await res.json()) as { stale: boolean }).stale).toBe(true);
    expect(((await (await call(env, "/badge/freshness.json")).json()) as { color: string }).color).toBe("red");
    expect(await (await call(env, "/")).text()).toContain("Stale: this snapshot was built 2026-10-24 03:05 UTC, 36 hours ago.");
    expect((await call(setup().env, "/status.json")).status).toBe(503);
  });
});

describe("atom feed", () => {
  const history = [
    { day: "2026-10-22", generated: "2026-10-23T03:05:00Z", ips_7d: 3000, active_24h: 1500, added: 120, removed: 98, cves: 9, urls: 3, hashes: 1, scanners: 3700, anonymizers: 40 },
    { day: "2026-10-23", generated: "2026-10-24T03:05:00Z", ips_7d: 3115, active_24h: 1566, added: 210, removed: 95, cves: 10, urls: 2, hashes: 2, scanners: 3736, anonymizers: 41 },
    { day: "bad<", generated: "x" },
  ];

  it("has one entry per build, newest first", async () => {
    const { env, r2 } = setup();
    r2.put("history.json", JSON.stringify(history));
    const res = await call(env, "/feed.atom");
    expect(res.headers.get("content-type")).toBe("application/atom+xml; charset=utf-8");
    const xml = await res.text();
    expect(xml.match(/<entry>/g)).toHaveLength(2);
    expect(xml.indexOf("build/2026-10-23")).toBeLessThan(xml.indexOf("build/2026-10-22"));
    expect(xml).toContain("<updated>2026-10-24T03:05:00Z</updated>\n<author>");
    expect(xml).toContain("3,115 IPs in the 7-day list (210 added, 95 removed)");
    expect(xml).not.toContain("bad<");
  });

  it("is a valid empty feed without history.json", async () => {
    const xml = await (await call(setup().env, "/feed.atom")).text();
    expect(xml).toContain('<feed xmlns="http://www.w3.org/2005/Atom">');
    expect(xml).not.toContain("<entry>");
    expect(renderAtom(null, NOW)).toContain("<updated>2026-10-24T09:00:00.000Z</updated>");
  });

  it("is linked from every page head", async () => {
    expect(await (await call(setup().env, "/privacy")).text()).toContain('<link rel="alternate" type="application/atom+xml" title="Mirage Feed builds" href="/feed.atom">');
  });
});

describe("address parsing", () => {
  it.each([
    ["9.9.9.9", "9.9.9.9", "9.9.9.9"],
    ["2a01:4f8:1:2::5", "2a01:4f8:1:2::/64", "2a01:4f8:1:2::"],
    ["2A01:04F8:0001:0002:aaaa:bbbb:cccc:dddd", "2a01:4f8:1:2::/64", "2a01:4f8:1:2::"],
    ["2a01:4f8:1:2::/64", "2a01:4f8:1:2::/64", "2a01:4f8:1:2::"],
    ["2a01::1", "2a01::/64", "2a01::"],
  ])("%s -> %s", (input, value, slug) => expect(parseAddr(input)).toMatchObject({ value, slug }));

  it.each(["", "10.0.0.1", "9.9.9.9/32", "2a01:4f8::/48", "::ffff:8.8.8.8", "fe80::1", "2001:db8::1", "3fff::1", "2002:c000:204::1", "2001::1", "example.com", "1.2.3.4<", "9".repeat(70)])(
    "rejects %j",
    (input) => expect(parseAddr(input)).toBeNull(),
  );
});

describe("/ip lookup", () => {
  it.each([
    ["/ip/8.8.8.8/", "/ip/8.8.8.8"],
    ["/ip/8.8.8.8.json/", "/ip/8.8.8.8.json"],
    ["/ip/2a01:4f8::1/64/", "/ip/2a01:4f8::"],
  ])("redirects a trailing slash on %s to the canonical address", async (path, location) => {
    const res = await call(setup().env, path);
    expect(res.status).toBe(301);
    expect(res.headers.get("location")).toBe(location);
  });

  it("shows a listed address with its lists, record and removal link", async () => {
    const { env, r2 } = setup();
    lookupData(r2);
    const res = await call(env, "/ip/9.9.9.9");
    expect(res.status).toBe(200);
    expect(res.headers.get("x-robots-tag")).toBe("noindex");
    const html = await res.text();
    expect(html).toContain('<meta name="robots" content="noindex,nofollow">');
    expect(html).not.toContain('rel="canonical"');
    expect(html).toContain("Listed. Mirage sensors");
    expect(html).toContain('<a rel="noreferrer" href="/mirage-feed/latest/ipv4-1d.txt">ipv4-1d.txt</a>, <a rel="noreferrer" href="/mirage-feed/latest/ipv4-7d.txt">ipv4-7d.txt</a>, <a rel="noreferrer" href="/mirage-feed/latest/ipv4-30d.txt">ipv4-30d.txt</a>');
    expect(res.headers.get("referrer-policy")).toBe("no-referrer");
    expect(html.match(/<a /g)!.length).toBe(html.match(/<a rel="noreferrer" /g)!.length);
    expect((await call(env, "/")).headers.get("referrer-policy")).toBe("strict-origin-when-cross-origin");
    expect(html).toContain('<a rel="noreferrer" href="https://mirage.offseq.com/cve/CVE-2024-3400">CVE-2024-3400</a>');
    expect(html).toContain('<a rel="noreferrer" href="https://attack.mitre.org/techniques/T1110/001/">T1110.001</a>');
    expect(html).toContain("AS64500 Example Hosting");
    expect(html).toContain("5 sensors in 3 networks, 812 hits");
    expect(html).toContain("88 / 100");
    expect(html).toContain('href="/removal?ip=9.9.9.9"');
    expect(html).toContain("utm_content=ip-lookup");
  });

  it("explains scanners, anonymizers and unlisted addresses", async () => {
    const { env, r2 } = setup();
    lookupData(r2);
    expect(await (await call(env, "/ip/71.6.135.131")).text()).toContain("Known research scanner.");
    expect(await (await call(env, "/ip/45.9.0.1")).text()).toContain("VPN or Tor exit seen attacking.");
    const none = await (await call(env, "/ip/1.1.1.1")).text();
    expect(none).toContain("Not listed.");
    expect(none).not.toContain("/removal?ip=");
  });

  it("normalises IPv6 to its /64 and redirects to the canonical path", async () => {
    const { env, r2 } = setup();
    lookupData(r2);
    const moved = await call(env, "/ip/2a01:4f8:1:2:dead:beef::1");
    expect(moved.status).toBe(301);
    expect(moved.headers.get("location")).toBe("/ip/2a01:4f8:1:2::");
    const res = await call(env, "/ip/2a01:4f8:1:2::.json");
    expect(await res.json()).toMatchObject({ ip: "2a01:4f8:1:2::/64", listed: true, lists: ["ipv6-7d.txt"], record: { asn: 64500 } });
  });

  it("redirects /ip/ to the form and sandboxes lookup JSON like a data file", async () => {
    const { env, r2 } = setup();
    lookupData(r2);
    const slash = await call(env, "/ip/");
    expect(slash.status).toBe(302);
    expect(slash.headers.get("location")).toBe("/ip");
    const json = await call(env, "/ip/9.9.9.9.json");
    expect(json.headers.get("content-security-policy")).toBe("default-src 'none'; frame-ancestors 'none'; sandbox");
  });

  it("redirects the no-JS form and rejects bad input with a 400", async () => {
    const env = setup().env;
    const ok = await call(env, "/ip?addr=%209.9.9.9%20");
    expect(ok.status).toBe(302);
    expect(ok.headers.get("location")).toBe("/ip/9.9.9.9");
    const bad = await call(env, "/ip?addr=10.0.0.1");
    expect(bad.status).toBe(400);
    expect(await bad.text()).toContain("<title>Error: Look up an address</title>");
    expect((await call(env, "/ip/%3Cscript%3E")).status).toBe(400);
    expect((await call(env, "/ip/%E0%A4%A")).status).toBe(400);
    expect((await call(env, "/ip")).status).toBe(200);
  });

  it("labels a 30-day-only hit and sends no CSP report endpoint on lookup pages", async () => {
    const { env, r2 } = setup();
    lookupData(r2);
    const res = await call(env, "/ip/8.8.4.4");
    expect(await res.text()).toContain("Listed in ipv4-30d.txt only.");
    const csp = res.headers.get("content-security-policy")!;
    expect(csp).not.toContain("report-uri");
    expect(csp).not.toContain("cloudflareinsights");
    expect(csp).not.toContain("in.ainalytic.net");
    expect(res.headers.get("cache-control")).toBe("private, max-age=300, no-transform");
    expect((await call(env, "/ip/10.0.0.1")).headers.get("cache-control")).toBe("no-store, no-transform");
    expect((await call(env, "/")).headers.get("content-security-policy")).toContain("report-uri");
  });

  it("answers 503 for a corrupt or unreadable shard, never Not listed", async () => {
    const bad = setup();
    lookupData(bad.r2);
    bad.r2.put("latest/lookup/v4/9.json", "{not json");
    expect((await call(bad.env, "/ip/9.9.9.9")).status).toBe(503);
    const down = setup();
    lookupData(down.r2);
    down.r2.failing = true;
    vi.stubGlobal("fetch", vi.fn(async () => new Response("upstream down", { status: 500 })));
    expect((await call(down.env, "/ip/9.9.9.9")).status).toBe(503);
  });

  it("answers 503 while the published build has no shard index", async () => {
    const { env, r2 } = setup();
    lookupData(r2);
    const feed = JSON.parse(fixture("feed.json"));
    feed.files = feed.files.filter((f: { path: string }) => f.path !== "latest/lookup/");
    r2.put("feed.json", JSON.stringify(feed));
    expect((await call(env, "/ip/1.7.51.205")).status).toBe(503);
  });

  it("rate limits per client, an IPv6 client per /64, and answers 503 before the first build", async () => {
    const keys: string[] = [];
    const limited = setup({ LOOKUP_LIMIT: { limit: async ({ key }: { key: string }) => (keys.push(key), { success: false }) } });
    const res = await call(limited.env, "/ip/9.9.9.9.json", { headers: { "cf-connecting-ip": "198.51.100.9" } });
    expect(res.status).toBe(429);
    expect(res.headers.get("retry-after")).toBe("60");
    await call(limited.env, "/ip/9.9.9.9.json", { headers: { "cf-connecting-ip": "2a01:4f8:1:2:dead:beef::1" } });
    expect(keys).toEqual(["198.51.100.9", "2a01:4f8:1:2::/64"]);
    expect((await call(setup().env, "/ip/9.9.9.9")).status).toBe(503);
  });

  it("reads one shard per lookup and counts only the outcome", async () => {
    const { env, r2, points } = setup();
    lookupData(r2);
    await call(env, "/ip/9.9.9.9");
    await call(env, "/ip/1.1.1.1");
    expect(r2.gets.filter((k) => k.startsWith("latest/"))).toEqual(["latest/lookup/v4/9.json", "latest/lookup/v4/1.json"]);
    expect(points.map((p) => p.blobs![3])).toEqual(["listed", "not-listed"]);
    expect(JSON.stringify(points)).not.toContain("9.9.9.9");
  });
});

describe("rate limit keys", () => {
  it.each([
    ["198.51.100.9", "198.51.100.9"],
    ["2a01:4f8:1:2:dead:beef::1", "2a01:4f8:1:2::/64"],
    ["2A01:04F8:0001:0002::", "2a01:4f8:1:2::/64"],
    ["", ""],
  ])("%s -> %s", (ip, key) => expect(limitKey(ip)).toBe(key));
});

describe("page metadata", () => {
  it("carries Open Graph, Twitter, theme-color and a Dataset JSON-LD block on /", async () => {
    const { env, r2 } = setup();
    published(r2);
    const html = await (await call(env, "/")).text();
    for (const tag of [
      '<meta property="og:type" content="website">',
      '<meta property="og:site_name" content="OffSeq Mirage">',
      '<meta property="og:url" content="https://feeds.offseq.com/">',
      '<meta property="og:image" content="https://feeds.offseq.com/og.png">',
      '<meta property="og:image:width" content="1200">',
      '<meta name="twitter:card" content="summary_large_image">',
      '<meta name="theme-color" content="#f9f7f2" media="(prefers-color-scheme: light)">',
      '<meta name="theme-color" content="#101821" media="(prefers-color-scheme: dark)">',
      '<link rel="apple-touch-icon" href="/apple-touch-icon.png">',
    ]) {
      expect(html).toContain(tag);
    }
    const ld = JSON.parse(/<script type="application\/ld\+json">([^<]*)<\/script>/.exec(html)![1]);
    expect(ld).toMatchObject({
      "@type": "Dataset",
      sameAs: "https://github.com/offseq/mirage-feed",
      license: "https://creativecommons.org/licenses/by/4.0/",
      isAccessibleForFree: true,
      creator: { "@type": "Organization", name: "OffSeq", url: "https://offseq.com" },
      dateModified: "2026-10-24T03:05:00Z",
      temporalCoverage: "2026-10-17/2026-10-24",
    });
    expect(ld.description.length).toBeGreaterThanOrEqual(50);
    expect(ld.distribution).toContainEqual({
      "@type": "DataDownload",
      contentUrl: "https://feeds.offseq.com/mirage-feed/latest/records-7d.ndjson.gz",
      encodingFormat: "application/gzip",
      description: "Gzip-compressed NDJSON, one indicator record per line.",
    });
    const odd = setup();
    published(odd.r2, "2026-10-24Tzz");
    const res = await call(odd.env, "/");
    expect(res.status).toBe(200);
    expect(await res.text()).toContain('"temporalCoverage":"P7D"');
    expect(ld.distribution.every((d: { encodingFormat?: string }) => d.encodingFormat)).toBe(true);
  });

  it("gives each page its own description, no canonical on 404 and noindex on /removal/sent", async () => {
    const env = setup().env;
    const desc = async (p: string) => /<meta name="description" content="([^"]*)">/.exec(await (await call(env, p)).text())![1];
    const all = await Promise.all(["/", "/removal", "/privacy", "/removal/sent", "/nope"].map(desc));
    expect(new Set(all).size).toBe(all.length);
    const missing = await (await call(env, "/nope")).text();
    expect(missing).not.toContain('rel="canonical"');
    const sent = await call(env, "/removal/sent");
    expect(sent.headers.get("x-robots-tag")).toBe("noindex");
    expect(await sent.text()).toContain('<meta name="robots" content="noindex,nofollow">');
  });

  it("sends every call to action through the premium sign-up deep link", async () => {
    const { env, r2 } = setup();
    lookupData(r2);
    const pages = await Promise.all(["/", "/ip/9.9.9.9", "/privacy", "/nope"].map(async (p) => (await call(env, p)).text()));
    const links = pages.flatMap((html) => [...html.matchAll(/href="(https:\/\/mirage\.offseq\.com[^"]*)"/g)].map((m) => m[1].replaceAll("&amp;", "&")));
    expect(pages.every((html) => /<a (?:rel="noreferrer" )?href="https:\/\/mirage\.offseq\.com">mirage\.offseq\.com<\/a>/.test(html))).toBe(true);
    const upsells = links.filter((u) => u.includes("?"));
    expect(upsells.length).toBeGreaterThanOrEqual(4);
    for (const u of upsells) {
      const q = new URL(u).searchParams;
      expect(q.get("auth")).toBe("signup");
      expect(q.get("intent")).toBe("premium");
      expect(q.get("utm_source")).toBe("feeds");
      expect(["hero", "compare", "ip-lookup", "status"]).toContain(q.get("utm_content"));
    }
    expect(new Set(upsells.map((u) => new URL(u).searchParams.get("utm_content")))).toEqual(new Set(["hero", "compare", "ip-lookup", "status"]));
    expect(links.filter((u) => u.includes("/cve/")).every((u) => !u.includes("?"))).toBe(true);
  });
});

describe("home content and accessibility", () => {
  async function homeHtml() {
    const { env, r2 } = setup();
    vi.spyOn(Date, "now").mockReturnValue(NOW);
    published(r2);
    return (await call(env, "/")).text();
  }

  it("makes code blocks keyboard scrollable and drops empty header cells", async () => {
    const html = await homeHtml();
    expect(html).not.toMatch(/<pre>/);
    expect(html).toContain('<pre tabindex="0" role="region" aria-label="FortiGate configuration">');
    expect(html).not.toContain('<th scope="col"></th>');
    expect(html).toMatch(/<a href="\/mirage-feed\/SHA256SUMS" aria-label="SHA-256 [0-9a-f]{64}, full list in SHA256SUMS">/);
  });

  it("matches the README recipes and listing rules", async () => {
    const html = await homeHtml();
    expect(html).toContain("threshold:type limit,track by_src,count 1,seconds 3600;");
    expect(html).toContain("match its <code>ip</code> column against <code>src_ip</code>");
    expect(html).toContain("scripts/sentinel-upload.sh");
    expect(html).toContain("one IPv4 address (/32) or one IPv6 /64");
    expect(html).not.toContain("wider than a /32");
    expect(html).toContain("latest/anonymizers-7d.txt");
    expect(html).toContain("latest/ipv4-added-1d.txt");
    expect(html).toContain("<h3>Which list do I want?</h3>");
    expect(html).toContain('<form class="lookup" method="get" action="/ip" role="search"');
    expect(html).toContain('href="/.well-known/mirage-feed-minisign.pub"');
  });

  it("points every CSS url() at a served path", async () => {
    const urls = [...CSS.matchAll(/url\(([^)#]+)\)/g)].map((m) => m[1]);
    expect(urls.length).toBe(2);
    const env = setup().env;
    for (const u of urls) {
      const res = await call(env, u);
      expect(res.status, u).toBe(200);
      expect(res.headers.get("content-type")).toBe("font/woff2");
    }
  });

  it("wraps long tokens instead of clipping at 320px", () => {
    expect(CSS).toContain("p,li{overflow-wrap:anywhere}");
    expect(CSS).not.toMatch(/\.cta\{[^}]*nowrap/);
  });

  it("describes the lookup and status endpoints in the privacy notice", async () => {
    const html = await (await call(setup().env, "/privacy")).text();
    expect(html).toContain("The addresses you look up are not logged");
    expect(html).toContain("<code>/status.json</code>");
    expect(html).not.toContain("no tracking scripts");
    expect(html).toContain("self-hosted Plausible at in.ainalytic.net");
    expect(html).toContain("Lookup pages send nothing to either analytics tool");
    expect(html).toContain("SEQ SIA, registration no. 40203410806");
  });
});
