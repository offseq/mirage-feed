import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { join, relative } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { call, setup } from "./harness";

// FEED_OUT=../out npx vitest run test/build.test.ts serves a real build the way the publish workflow lays it out.
const OUT = process.env.FEED_OUT;

const walk = (dir: string): string[] =>
  readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(dir, e.name)) : [join(dir, e.name)]));

function serveBuild() {
  const ctx = setup();
  const sums = readFileSync(join(OUT!, "SHA256SUMS"));
  const version = createHash("sha256").update(sums).digest("hex").slice(0, 16);
  for (const file of walk(OUT!)) ctx.r2.put(`builds/${version}/${relative(OUT!, file)}`, new Uint8Array(readFileSync(file)));
  const feed = JSON.parse(readFileSync(join(OUT!, "feed.json"), "utf8"));
  ctx.r2.put("_meta/published.json", JSON.stringify({ generated: feed.generated, day: feed.day, sha256sums: createHash("sha256").update(sums).digest("hex"), version }));
  vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 599 })));
  vi.spyOn(Date, "now").mockReturnValue(Date.parse(feed.generated) + 3600_000);
  return { ...ctx, feed, sums: sums.toString() };
}

const lines = (rel: string) => readFileSync(join(OUT!, rel), "utf8").split("\n").filter(Boolean);

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe.skipIf(!OUT)("a locally built feed", () => {
  it("serves every file in SHA256SUMS byte for byte", async () => {
    const { env, sums } = serveBuild();
    for (const line of sums.split("\n").filter(Boolean)) {
      const [hash, path] = line.split("  ");
      const res = await call(env, `/mirage-feed/${path}`);
      expect(res.status, path).toBe(200);
      expect(createHash("sha256").update(new Uint8Array(await res.arrayBuffer())).digest("hex"), path).toBe(hash);
    }
  });

  it("answers lookups from the shards in line with the lists", async () => {
    const { env } = serveBuild();
    const sample = (rel: string) => lines(rel).filter((_, i, all) => i % Math.max(1, Math.floor(all.length / 25)) === 0);
    const json = async (value: string) => (await call(env, `/ip/${value.replace(/\/64$/, "")}.json`)).json() as Promise<Record<string, unknown>>;
    for (const v of sample("latest/ipv4-7d.txt")) expect(await json(v), v).toMatchObject({ listed: true, scanner: false, record: expect.any(Object) });
    for (const v of sample("latest/ipv4-30d.txt")) expect(await json(v), v).toMatchObject({ listed: true });
    for (const v of sample("latest/ipv6-7d.txt")) expect(await json(v), v).toMatchObject({ listed: true, lists: expect.arrayContaining(["ipv6-7d.txt"]) });
    for (const v of sample("latest/anonymizers-7d.txt")) expect(await json(v), v).toMatchObject({ listed: false, anonymizer: true });
    for (const v of sample("latest/known-scanners-ipv4.txt")) expect(await json(v), v).toMatchObject({ listed: false, scanner: true });
    for (const v of sample("latest/ipv4-removed-1d.txt")) expect((await json(v)).lists, v).not.toContain("ipv4-7d.txt");
  });

  it("renders the home page, status and badges from the build", async () => {
    const { env, feed } = serveBuild();
    const home = await (await call(env, "/")).text();
    expect(home).toContain(`Snapshot of ${feed.day}`);
    expect(home).not.toContain("latest/lookup/");
    const status = (await (await call(env, "/status.json")).json()) as { stale: boolean; counts: { ips_7d: number } };
    expect(status.stale).toBe(false);
    expect(status.counts.ips_7d).toBe(lines("latest/ipv4-7d.txt").length + lines("latest/ipv6-7d.txt").length);
  });
});
