import { afterEach, describe, expect, it, vi } from "vitest";
import { contentType, isAllowedPath } from "../src/feed";
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
    "misp/manifest.json",
    "misp/5f0c0b6e-7a3d-4c8e-9f51-0d6e1c2a9b10.json",
    "schema/record.schema.json",
    "SHA256SUMS",
    "SHA256SUMS.minisig",
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
    ["latest/records-7d.ndjson", "application/x-ndjson"],
  ])("%s -> %s", (p, t) => expect(contentType(p)).toBe(t));
});

describe("serving from R2", () => {
  it("serves R2 objects with the R2 ETag, CORS, feed age and an aggregate-only data point", async () => {
    const { env, r2, points } = setup();
    r2.put("latest/ipv4-7d.txt", fixture("ipv4-7d.txt"));
    r2.put("_meta/published.json", JSON.stringify({ generated: new Date(Date.now() - 7200_000).toISOString() }));
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const res = await call(env, "/mirage-feed/latest/ipv4-7d.txt", { headers: { "user-agent": "curl/8.7.1" } });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe(fixture("ipv4-7d.txt"));
    expect(res.headers.get("content-type")).toBe("text/plain; charset=utf-8");
    expect(res.headers.get("etag")).toBe(r2.objects.get("latest/ipv4-7d.txt")!.etag);
    expect(res.headers.get("access-control-allow-origin")).toBe("*");
    expect(Number(res.headers.get("x-mirage-feed-age"))).toBeGreaterThanOrEqual(7200);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(points[0].blobs).toEqual(["latest/ipv4-7d.txt", "", "", "curl"]);
  });

  it("answers If-None-Match with 304 via R2 onlyIf and from the edge cache", async () => {
    const { env, r2 } = setup();
    r2.put("latest/ipv4-7d.txt", fixture("ipv4-7d.txt"));
    const etag = r2.objects.get("latest/ipv4-7d.txt")!.etag;
    const viaR2 = await call(env, "/mirage-feed/latest/ipv4-7d.txt", { headers: { "if-none-match": etag } });
    expect(viaR2.status).toBe(304);
    await call(env, "/mirage-feed/latest/ipv4-7d.txt");
    const viaCache = await call(env, "/mirage-feed/latest/ipv4-7d.txt", { headers: { "if-none-match": `W/${etag}` } });
    expect(viaCache.status).toBe(304);
    expect(await viaCache.text()).toBe("");
    const head = await call(env, "/mirage-feed/latest/ipv4-7d.txt", { method: "HEAD" });
    expect(head.status).toBe(200);
    expect(await head.text()).toBe("");
  });

  it("serves root feed.json and stats.json and collapses double slashes", async () => {
    const { env, r2 } = setup();
    r2.put("feed.json", fixture("feed.json"));
    r2.put("stats.json", fixture("stats.json"));
    r2.put("misp/manifest.json", "{}");
    expect((await call(env, "/feed.json")).headers.get("content-type")).toBe("application/json");
    expect((await call(env, "/stats.json")).status).toBe(200);
    expect((await call(env, "/mirage-feed//misp/manifest.json")).status).toBe(200);
  });

  it("answers CORS preflight", async () => {
    const { env } = setup();
    const res = await call(env, "/mirage-feed/latest/ipv4-7d.txt", { method: "OPTIONS" });
    expect(res.status).toBe(204);
    expect(res.headers.get("access-control-allow-methods")).toContain("GET");
  });
});

describe("raw GitHub fallback", () => {
  it("fetches raw.githubusercontent.com without a token only when R2 misses", async () => {
    const { env } = setup();
    const fetchMock = rawServing({ "latest/ipv4-7d.txt": fixture("ipv4-7d.txt") });
    vi.stubGlobal("fetch", fetchMock);
    const res = await call(env, "/mirage-feed/latest/ipv4-7d.txt");
    expect(res.status).toBe(200);
    expect(res.headers.get("etag")).toMatch(/^"[0-9a-f]{32}"$/);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(`${RAW}latest/ipv4-7d.txt`);
    expect(JSON.stringify(init.headers)).not.toMatch(/authorization/i);
    await call(env, "/mirage-feed/latest/ipv4-7d.txt");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("serves stale content on upstream error for up to 48 hours", async () => {
    const { env } = setup();
    const t0 = Date.now();
    const now = vi.spyOn(Date, "now").mockReturnValue(t0);
    vi.stubGlobal("fetch", rawServing({ "latest/ipv4-7d.txt": fixture("ipv4-7d.txt") }));
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
  });

  it("returns 404 when neither source has the file and caches the miss briefly", async () => {
    const { env } = setup();
    const fetchMock = rawServing({});
    vi.stubGlobal("fetch", fetchMock);
    expect((await call(env, "/mirage-feed/latest/ipv4-7d.txt")).status).toBe(404);
    expect((await call(env, "/mirage-feed/latest/ipv4-7d.txt")).status).toBe(404);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
