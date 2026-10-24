import { afterEach, describe, expect, it, vi } from "vitest";
import { contentType, isAllowedPath, parseRange } from "../src/feed";
import { RAW, call, fixture, rawServing, setup } from "./harness";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("path allowlist", () => {
  it.each([
    "latest/ipv4-7d.txt",
    "latest/known-scanners-ipv4.txt",
    "latest/known-scanners-ipv6.txt",
    "latest/attackers-ipv4-7d.csv",
    "latest/stix/mirage.json",
    "latest/records-7d.ndjson.gz",
    "latest/suricata/datasets/mirage-ipv4.lst",
    "latest/ipset/mirage.ipset",
    "latest/defender/defender-top500.csv",
    "latest/lookup/v4/198.json",
    "latest/lookup/v6/2a01.json",
    "misp/manifest.json",
    "misp/5f0c0b6e-7a3d-4c8e-9f51-0d6e1c2a9b10.json",
    "schema/record.schema.json",
    "SHA256SUMS",
    "SHA256SUMS.minisig",
    "LICENSE-DATA",
    "feed.json",
  ])("allows %s", (p) => expect(isAllowedPath(p)).toBe(true));

  it.each([
    "",
    "../wrangler.toml",
    "latest/../../secret.txt",
    "latest/..%2fsecret.txt",
    "latest/%2e%2e/x.txt",
    ".git/config",
    "_meta/published.json",
    "latest/.hidden.txt",
    "latest/a/b/c.txt",
    "latest/suricata/datasets/x/y.lst",
    "latest/unknown/x.txt",
    "latest/lookup/x.json",
    "latest/lookup/v5/1.json",
    "builds/0123456789abcdef/feed.json",
    "src/index.ts",
    "latest/ipv4-7d.exe",
    "latest/",
    "latest/x..txt",
    "latest\\x.txt",
    "latest/ipv4-7d.txt\n",
  ])("rejects %j", (p) => expect(isAllowedPath(p)).toBe(false));

  it("never touches R2 or GitHub for a rejected path", async () => {
    const { env, r2 } = setup();
    const fetchMock = rawServing({});
    vi.stubGlobal("fetch", fetchMock);
    for (const p of ["/mirage-feed/latest/..%2fx.txt", "/mirage-feed/latest%2f..%2f..%2fx.txt", "/mirage-feed/.git/config", "/mirage-feed/_meta/published.json"]) {
      expect((await call(env, p)).status).toBe(404);
    }
    expect(fetchMock).not.toHaveBeenCalled();
    expect(r2.gets).toEqual([]);
  });
});

describe("content types", () => {
  it.each([
    ["latest/ipv4-7d.txt", "text/plain; charset=utf-8"],
    ["latest/mikrotik/mirage-7d.rsc", "text/plain; charset=utf-8"],
    ["latest/nft/mirage.nft", "text/plain; charset=utf-8"],
    ["latest/zeek/mirage.intel", "text/plain; charset=utf-8"],
    ["latest/suricata/mirage-iprep.list", "text/plain; charset=utf-8"],
    ["latest/suricata/datasets/mirage-ipv4.lst", "text/plain; charset=utf-8"],
    ["latest/ipset/mirage.ipset", "text/plain; charset=utf-8"],
    ["latest/suricata/mirage.rules", "text/plain; charset=utf-8"],
    ["SHA256SUMS", "text/plain; charset=utf-8"],
    ["latest/attackers-7d.csv", "text/csv; charset=utf-8"],
    ["latest/stix/mirage.json", "application/json"],
    ["latest/records-7d.ndjson.gz", "application/gzip"],
  ])("%s -> %s", (p, t) => expect(contentType(p)).toBe(t));
});

describe("range parsing", () => {
  it.each([
    ["bytes=0-0", { offset: 0, length: 1 }],
    ["bytes=5-100", { offset: 5, length: 5 }],
    ["bytes=-20", { offset: 0, length: 10 }],
    ["bytes=10-", "unsatisfiable"],
    ["bytes=-0", "unsatisfiable"],
    ["bytes=5-2", null],
    ["bytes=-", null],
    ["items=0-1", null],
  ])("%s of 10 bytes", (h, want) => expect(parseRange(h, 10)).toEqual(want));
});

describe("serving from R2", () => {
  it("reads the build the pointer names and switches files and checksums together", async () => {
    const { env, r2 } = setup();
    const publish = (sums: string, body: string) => {
      const version = sums.repeat(16);
      r2.put(`builds/${version}/latest/ipv4-7d.txt`, body);
      r2.put(`builds/${version}/SHA256SUMS`, `${sums}  latest/ipv4-7d.txt\n`);
      r2.put("_meta/published.json", JSON.stringify({ generated: new Date().toISOString(), sha256sums: sums.repeat(64), version }));
    };
    vi.stubGlobal("fetch", vi.fn());
    r2.put("latest/ipv4-7d.txt", "203.0.113.250\n");
    publish("a", "198.51.100.1\n");
    expect(await (await call(env, "/mirage-feed/latest/ipv4-7d.txt")).text()).toBe("198.51.100.1\n");
    // Files of the next build are in place before the pointer moves; readers keep the old build until it does.
    r2.put(`builds/${"b".repeat(16)}/latest/ipv4-7d.txt`, "198.51.100.2\n");
    vi.spyOn(Date, "now").mockReturnValue(Date.now() + 61_000);
    expect(await (await call(env, "/mirage-feed/latest/ipv4-7d.txt")).text()).toBe("198.51.100.1\n");
    publish("b", "198.51.100.2\n");
    vi.spyOn(Date, "now").mockReturnValue(Date.now() + 122_000);
    expect(await (await call(env, "/mirage-feed/latest/ipv4-7d.txt")).text()).toBe("198.51.100.2\n");
    expect(await (await call(env, "/mirage-feed/SHA256SUMS")).text()).toBe("b  latest/ipv4-7d.txt\n");
  });

  it("reads the bucket root while the pointer predates build prefixes", async () => {
    const { env, r2 } = setup();
    r2.put("latest/ipv4-7d.txt", "198.51.100.1\n");
    r2.put("_meta/published.json", JSON.stringify({ generated: new Date().toISOString(), sha256sums: "a".repeat(64) }));
    expect(await (await call(env, "/mirage-feed/latest/ipv4-7d.txt")).text()).toBe("198.51.100.1\n");
    expect(r2.gets).toContain("latest/ipv4-7d.txt");
  });

  it("caches the index files for five minutes and data files for an hour", async () => {
    const { env, r2 } = setup();
    for (const p of ["feed.json", "stats.json", "history.json", "SHA256SUMS", "SHA256SUMS.minisig", "latest/ipv4-7d.txt", "misp/manifest.json"]) r2.put(p, "x");
    for (const p of ["feed.json", "stats.json", "history.json", "SHA256SUMS", "SHA256SUMS.minisig"]) {
      expect((await call(env, `/mirage-feed/${p}`)).headers.get("cache-control")).toBe("public, max-age=300");
    }
    expect((await call(env, "/mirage-feed/latest/ipv4-7d.txt")).headers.get("cache-control")).toBe("public, max-age=3600");
    expect((await call(env, "/mirage-feed/misp/manifest.json")).headers.get("cache-control")).toBe("public, max-age=3600");
  });


  it("serves R2 objects with the R2 ETag, CORS, feed age and an aggregate-only data point", async () => {
    const { env, r2, points } = setup();
    r2.put("latest/ipv4-7d.txt", fixture("ipv4-7d.txt"));
    r2.put("_meta/published.json", JSON.stringify({ generated: new Date(Date.now() - 7200_000).toISOString() }));
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const res = await call(env, "/mirage-feed/latest/ipv4-7d.txt", { headers: { "user-agent": "curl/8.7.1" } });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe(fixture("ipv4-7d.txt"));
    const h = res.headers;
    expect(h.get("content-type")).toBe("text/plain; charset=utf-8");
    expect(h.get("etag")).toBe(r2.objects.get("latest/ipv4-7d.txt")!.etag);
    expect(h.get("last-modified")).toBe("Sat, 24 Oct 2026 03:05:00 GMT");
    expect(h.get("content-length")).toBe(String(fixture("ipv4-7d.txt").length));
    expect(h.get("accept-ranges")).toBe("bytes");
    expect(h.get("cache-control")).toBe("public, max-age=3600");
    expect(h.get("access-control-allow-origin")).toBe("*");
    expect(h.get("access-control-expose-headers")).toBe("etag, last-modified, content-range, accept-ranges, x-mirage-feed-age");
    expect(h.get("cross-origin-resource-policy")).toBe("cross-origin");
    expect(h.get("x-robots-tag")).toBe("noindex");
    expect(h.get("content-security-policy")).toBe("default-src 'none'; frame-ancestors 'none'; sandbox");
    expect(Number(h.get("x-mirage-feed-age"))).toBeGreaterThanOrEqual(7200);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(points[0].blobs).toEqual(["latest/ipv4-7d.txt", "", "", "curl"]);
    const cached = await call(env, "/mirage-feed/latest/ipv4-7d.txt");
    expect(cached.headers.get("content-length")).toBe(String(fixture("ipv4-7d.txt").length));
    expect(await cached.text()).toBe(fixture("ipv4-7d.txt"));
  });

  it("serves the social cards listed in SHA256SUMS", async () => {
    const { env, r2 } = setup();
    r2.put("og.png", "card");
    const res = await call(env, "/mirage-feed/og.png");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("image/png");
  });

  it("answers If-None-Match and If-Modified-Since with 304, from R2 and from the edge cache", async () => {
    const { env, r2 } = setup();
    r2.put("latest/ipv4-7d.txt", fixture("ipv4-7d.txt"));
    const etag = r2.objects.get("latest/ipv4-7d.txt")!.etag;
    const url = "/mirage-feed/latest/ipv4-7d.txt";
    const viaR2 = await call(env, url, { headers: { "if-none-match": etag } });
    expect(viaR2.status).toBe(304);
    expect(viaR2.headers.get("etag")).toBe(etag);
    const viaCache = await call(env, url, { headers: { "if-none-match": `W/${etag}` } });
    expect(viaCache.status).toBe(304);
    expect(await viaCache.text()).toBe("");
    expect(r2.gets.filter((k) => k === "latest/ipv4-7d.txt")).toHaveLength(1);
    expect((await call(env, url)).status).toBe(200);
    expect((await call(env, url, { headers: { "if-modified-since": "Sat, 24 Oct 2026 03:05:00 GMT" } })).status).toBe(304);
    expect((await call(env, url, { headers: { "if-modified-since": "Fri, 23 Oct 2026 00:00:00 GMT" } })).status).toBe(200);
    // If-None-Match wins over If-Modified-Since, and a failed If-Match is never a 304.
    expect((await call(env, url, { headers: { "if-none-match": '"other"', "if-modified-since": "Sat, 24 Oct 2026 03:05:00 GMT" } })).status).toBe(200);
    expect((await call(env, url, { headers: { "if-match": '"other"' } })).status).toBe(200);
  });

  it("sends Content-Length on HEAD and does not count HEAD or prefetch as a fetch", async () => {
    const { env, r2, points } = setup();
    r2.put("latest/ipv4-7d.txt", fixture("ipv4-7d.txt"));
    const head = await call(env, "/mirage-feed/latest/ipv4-7d.txt", { method: "HEAD" });
    expect(head.status).toBe(200);
    expect(await head.text()).toBe("");
    expect(head.headers.get("content-length")).toBe(String(fixture("ipv4-7d.txt").length));
    await call(env, "/mirage-feed/latest/ipv4-7d.txt", { headers: { "sec-purpose": "prefetch" } });
    expect(points).toHaveLength(0);
    await call(env, "/mirage-feed/latest/ipv4-7d.txt");
    expect(points).toHaveLength(1);
  });

  it("serves byte ranges with 206 and 416", async () => {
    const { env, r2 } = setup();
    r2.put("latest/stix/mirage.json", "0123456789");
    const url = "/mirage-feed/latest/stix/mirage.json";
    const part = await call(env, url, { headers: { range: "bytes=2-5" } });
    expect(part.status).toBe(206);
    expect(await part.text()).toBe("2345");
    expect(part.headers.get("content-range")).toBe("bytes 2-5/10");
    expect(part.headers.get("content-length")).toBe("4");
    expect(await (await call(env, url, { headers: { range: "bytes=-3" } })).text()).toBe("789");
    expect(await (await call(env, url, { headers: { range: "bytes=7-" } })).text()).toBe("789");
    const bad = await call(env, url, { headers: { range: "bytes=10-" } });
    expect(bad.status).toBe(416);
    expect(bad.headers.get("content-range")).toBe("bytes */10");
    expect((await call(env, url, { headers: { range: "bytes=0-1,4-5" } })).status).toBe(200);
    expect((await call(env, url, { headers: { range: "bytes=2-5", "if-range": '"stale"' } })).status).toBe(200);
  });

  it("serves root feed.json, stats.json and history.json and collapses double slashes", async () => {
    const { env, r2 } = setup();
    r2.put("feed.json", fixture("feed.json"));
    r2.put("stats.json", fixture("stats.json"));
    r2.put("history.json", "[]");
    r2.put("misp/manifest.json", "{}");
    expect((await call(env, "/feed.json")).headers.get("content-type")).toBe("application/json");
    expect((await call(env, "/stats.json")).status).toBe(200);
    expect((await call(env, "/history.json")).status).toBe(200);
    expect((await call(env, "/mirage-feed//misp/manifest.json")).status).toBe(200);
  });

  it("answers CORS preflight", async () => {
    const { env } = setup();
    const res = await call(env, "/mirage-feed/latest/ipv4-7d.txt", { method: "OPTIONS" });
    expect(res.status).toBe(204);
    expect(res.headers.get("access-control-allow-methods")).toBe("GET, HEAD, OPTIONS");
    expect(res.headers.get("access-control-allow-headers")).toBe("If-None-Match, If-Modified-Since, Range");
    expect(res.headers.get("access-control-max-age")).toBe("86400");
  });

  it("answers a clean R2 miss with a cached 404 and never asks GitHub", async () => {
    const { env } = setup();
    const fetchMock = rawServing({ "latest/ipv4-7d.txt": fixture("ipv4-7d.txt") });
    vi.stubGlobal("fetch", fetchMock);
    const res = await call(env, "/mirage-feed/latest/ipv4-7d.txt");
    expect(res.status).toBe(404);
    expect(res.headers.get("cache-control")).toBe("public, max-age=300");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("raw GitHub fallback", () => {
  function failingR2(files: Record<string, string>) {
    const ctx = setup();
    ctx.r2.failing = true;
    const fetchMock = rawServing({ "feed.json": fixture("feed.json"), ...files });
    vi.stubGlobal("fetch", fetchMock);
    return { ...ctx, fetchMock };
  }

  it("fetches raw.githubusercontent.com without a token only when R2 errors", async () => {
    const { env, fetchMock } = failingR2({ "latest/ipv4-7d.txt": fixture("ipv4-7d.txt") });
    const res = await call(env, "/mirage-feed/latest/ipv4-7d.txt");
    expect(res.status).toBe(200);
    expect(res.headers.get("etag")).toMatch(/^"[0-9a-f]{32}"$/);
    const urls = (fetchMock.mock.calls as unknown as [string, RequestInit][]).map(([u]) => u);
    expect(urls).toContain(`${RAW}latest/ipv4-7d.txt`);
    for (const [, init] of fetchMock.mock.calls as unknown as [string, RequestInit][]) {
      expect(JSON.stringify(init.headers)).not.toMatch(/authorization/i);
    }
    const before = fetchMock.mock.calls.length;
    await call(env, "/mirage-feed/latest/ipv4-7d.txt");
    expect(fetchMock).toHaveBeenCalledTimes(before);
  });

  it("only falls back for paths the current feed.json lists", async () => {
    const { env, fetchMock } = failingR2({ "latest/random-name.txt": "x\n" });
    expect((await call(env, "/mirage-feed/latest/random-name.txt")).status).toBe(404);
    const urls = (fetchMock.mock.calls as unknown as [string][]).map(([u]) => u);
    expect(urls).toEqual([`${RAW}feed.json`]);
  });

  it("falls back for lookup shards when feed.json lists the shard directory", async () => {
    const feed = JSON.stringify({ day: "2026-10-23", files: [{ path: "latest/lookup/" }] });
    const shard = JSON.stringify({ "9.9.9.9": { lists: ["ipv4-7d.txt"] } });
    const { env } = failingR2({ "feed.json": feed, "latest/lookup/v4/9.json": shard });
    const res = await call(env, "/ip/9.9.9.9.json");
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ listed: true, lists: ["ipv4-7d.txt"], day: "2026-10-23" });
  });

  it("serves stale content on upstream error for up to 48 hours", async () => {
    const { env } = failingR2({ "latest/ipv4-7d.txt": fixture("ipv4-7d.txt") });
    const t0 = Date.now();
    const now = vi.spyOn(Date, "now").mockReturnValue(t0);
    await call(env, "/mirage-feed/latest/ipv4-7d.txt");

    vi.stubGlobal("fetch", vi.fn(async () => new Response("boom", { status: 503 })));
    now.mockReturnValue(t0 + 2 * 3600_000);
    const stale = await call(env, "/mirage-feed/latest/ipv4-7d.txt");
    expect(stale.status).toBe(200);
    expect(stale.headers.get("x-mirage-stale")).toBe("1");
    expect(await stale.text()).toBe(fixture("ipv4-7d.txt"));

    vi.stubGlobal("fetch", vi.fn(async () => Promise.reject(new Error("network down"))));
    now.mockReturnValue(t0 + 47 * 3600_000);
    expect((await call(env, "/mirage-feed/latest/ipv4-7d.txt")).status).toBe(200);

    now.mockReturnValue(t0 + 49 * 3600_000);
    const gone = await call(env, "/mirage-feed/latest/ipv4-7d.txt");
    expect(gone.status).toBe(502);
    expect(gone.headers.get("retry-after")).toBe("300");
    expect(gone.headers.get("cache-control")).toBe("no-store");
  });

  it("returns 404 when R2 errors and GitHub has no copy, and caches the miss briefly", async () => {
    const { env, fetchMock } = failingR2({});
    expect((await call(env, "/mirage-feed/latest/ipv4-7d.txt")).status).toBe(404);
    const before = fetchMock.mock.calls.length;
    expect((await call(env, "/mirage-feed/latest/ipv4-7d.txt")).status).toBe(404);
    expect(fetchMock).toHaveBeenCalledTimes(before);
  });
});
