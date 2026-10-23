import { readFileSync } from "node:fs";
import { vi } from "vitest";
import worker from "../src/index";
import type { Env } from "../src/env";

class MemoryCache {
  store = new Map<string, { body: ArrayBuffer; init: ResponseInit; expires: number }>();
  async match(req: Request) {
    const hit = this.store.get(req.url);
    if (!hit || hit.expires <= Date.now()) return undefined;
    return new Response(hit.body.slice(0), hit.init);
  }
  async put(req: Request, res: Response) {
    const maxAge = Number(/max-age=(\d+)/.exec(res.headers.get("cache-control") ?? "")?.[1] ?? 0);
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => (headers[k] = v));
    this.store.set(req.url, { body: await res.arrayBuffer(), init: { status: res.status, headers }, expires: Date.now() + maxAge * 1000 });
  }
}

export class MemoryR2 {
  objects = new Map<string, { body: Uint8Array; etag: string }>();
  gets: string[] = [];
  put(key: string, text: string) {
    const body = new TextEncoder().encode(text);
    this.objects.set(key, { body, etag: `"r2-${key.length}-${body.byteLength}"` });
  }
  async get(key: string, opts?: { onlyIf?: Headers }) {
    this.gets.push(key);
    const o = this.objects.get(key);
    if (!o) return null;
    const meta = { key, size: o.body.byteLength, httpEtag: o.etag };
    if (opts?.onlyIf?.get("if-none-match") === o.etag) return meta;
    return {
      ...meta,
      body: new Blob([o.body]).stream(),
      arrayBuffer: async () => o.body.slice().buffer,
      json: async () => JSON.parse(new TextDecoder().decode(o.body)),
    };
  }
}

export const fixture = (name: string) => readFileSync(new URL(`../fixtures/${name}`, import.meta.url), "utf8");

export function setup(overrides: Partial<Env> = {}) {
  const cache = new MemoryCache();
  vi.stubGlobal("caches", { default: cache });
  const r2 = new MemoryR2();
  const points: AnalyticsEngineDataPoint[] = [];
  const env: Env = {
    FEED: r2 as unknown as R2Bucket,
    GITHUB_REPO: "offseq/mirage-feed",
    GITHUB_REF: "data",
    REMOVAL_UPSTREAM: "https://mirage.example/api/feed/removal",
    FEED_PROXY_SECRET: "proxy-secret",
    TURNSTILE_SITEKEY: "1x00000000000000000000AA",
    TURNSTILE_SECRET: "turnstile-secret",
    FETCHES: { writeDataPoint: (p?: AnalyticsEngineDataPoint) => p && points.push(p) },
    ...overrides,
  };
  return { cache, env, points, r2 };
}

export async function call(env: Env, path: string, init: RequestInit = {}) {
  const pending: Promise<unknown>[] = [];
  const ctx = { waitUntil: (p: Promise<unknown>) => pending.push(p), passThroughOnException() {} } as unknown as ExecutionContext;
  const res = await worker.fetch(new Request(`https://feeds.offseq.com${path}`, init) as never, env, ctx);
  await Promise.all(pending);
  return res;
}

export const RAW = "https://raw.githubusercontent.com/offseq/mirage-feed/data/";

export function rawServing(files: Record<string, string>) {
  return vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input instanceof Request ? input.url : input);
    const body = url.startsWith(RAW) ? files[decodeURIComponent(url.slice(RAW.length))] : undefined;
    return body === undefined ? new Response("404: Not Found", { status: 404 }) : new Response(body);
  });
}
