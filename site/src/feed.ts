import { isShadow, type Env } from "./env";

const TEXT = "text/plain; charset=utf-8";
const TYPES: Record<string, string> = {
  txt: TEXT,
  rsc: TEXT,
  nft: TEXT,
  intel: TEXT,
  list: TEXT,
  lst: TEXT,
  ipset: TEXT,
  rules: TEXT,
  minisig: TEXT,
  csv: "text/csv; charset=utf-8",
  json: "application/json",
  gz: "application/gzip",
  ndjson: "application/x-ndjson",
};

const DIR_RE = /^(?:latest(?:\/(?:stix|zeek|suricata(?:\/datasets)?|mikrotik|nft|ipset|crowdsec|defender))?|misp|schema)$/;
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

export const FRESH_TTL = 3600;
export const STALE_TTL = 48 * 3600;
const MISSING_TTL = 300;
const META_TTL_MS = 300_000;
const MISSING = "x-mirage-missing";
export const STALE = "x-mirage-stale";

export function contentType(path: string): string | null {
  const name = path.slice(path.lastIndexOf("/") + 1);
  if (name === "SHA256SUMS") return TEXT;
  const dot = name.lastIndexOf(".");
  return dot > 0 ? (TYPES[name.slice(dot + 1)] ?? null) : null;
}

export function isAllowedPath(path: string): boolean {
  const slash = path.lastIndexOf("/");
  const dir = slash < 0 ? "" : path.slice(0, slash);
  const name = path.slice(slash + 1);
  return (dir === "" || DIR_RE.test(dir)) && NAME_RE.test(name) && !name.includes("..") && contentType(path) !== null;
}

async function sha256Etag(body: ArrayBuffer): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", body));
  return `"${[...digest.slice(0, 16)].map((b) => b.toString(16).padStart(2, "0")).join("")}"`;
}

async function fromR2(env: Env, path: string, cond?: Headers): Promise<R2Object | R2ObjectBody | null> {
  try {
    return await env.FEED.get(path, cond ? { onlyIf: cond } : undefined);
  } catch {
    return null;
  }
}

async function fromRaw(env: Env, path: string): Promise<Response | null> {
  const segments = path.split("/").map(encodeURIComponent).join("/");
  try {
    return await fetch(`https://raw.githubusercontent.com/${env.GITHUB_REPO}/${env.GITHUB_REF}/${segments}`, {
      headers: { "user-agent": "mirage-feed-site" },
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    return null;
  }
}

const cacheKey = (origin: string, kind: string, path: string) => new Request(`${origin}/__cache/${kind}/${path}`);
const withTtl = (body: ArrayBuffer, headers: Record<string, string>, ttl: number) =>
  new Response(body.slice(0), { headers: { ...headers, "cache-control": `max-age=${ttl}` } });

// R2 is the source of truth; the raw GitHub fallback is the only path that keeps a 48h stale copy.
export async function getFeedFile(path: string, env: Env, origin: string, ctx: ExecutionContext, cond?: Headers): Promise<Response> {
  const cache = caches.default;
  const freshKey = cacheKey(origin, "fresh", path);

  const hit = await cache.match(freshKey);
  if (hit) return hit.headers.has(MISSING) ? new Response(null, { status: 404 }) : hit;

  const type = contentType(path) ?? TEXT;
  const obj = await fromR2(env, path, cond);
  if (obj) {
    const headers = { "content-type": type, etag: obj.httpEtag };
    if (!("body" in obj)) return new Response(null, { status: 304, headers });
    const body = await obj.arrayBuffer();
    ctx.waitUntil(cache.put(freshKey, withTtl(body, headers, FRESH_TTL)));
    return new Response(body, { headers });
  }

  const staleKey = cacheKey(origin, "stale", path);
  const upstream = await fromRaw(env, path);
  if (upstream?.ok) {
    const body = await upstream.arrayBuffer();
    const headers = { "content-type": type, etag: await sha256Etag(body) };
    ctx.waitUntil(Promise.all([cache.put(freshKey, withTtl(body, headers, FRESH_TTL)), cache.put(staleKey, withTtl(body, headers, STALE_TTL))]));
    return new Response(body, { headers });
  }
  if (upstream?.status === 404) {
    ctx.waitUntil(cache.put(freshKey, new Response("", { headers: { [MISSING]: "1", "cache-control": `max-age=${MISSING_TTL}` } })));
    return new Response(null, { status: 404 });
  }

  const stale = await cache.match(staleKey);
  if (!stale) return new Response(null, { status: 502 });
  const served = new Response(stale.body, stale);
  served.headers.set(STALE, "1");
  return served;
}

export async function getFeedJson<T>(path: string, env: Env, origin: string, ctx: ExecutionContext): Promise<T | null> {
  try {
    const res = await getFeedFile(path, env, origin, ctx);
    return res.ok ? ((await res.json()) as T) : null;
  } catch {
    return null;
  }
}

const generatedMemo = new WeakMap<R2Bucket, { at: number; generated: number | null }>();

export async function publishedAt(env: Env): Promise<number | null> {
  const memo = generatedMemo.get(env.FEED);
  if (memo && Date.now() - memo.at < META_TTL_MS) return memo.generated;
  let generated: number | null = null;
  const obj = await fromR2(env, "_meta/published.json");
  if (obj && "body" in obj) {
    try {
      const t = Date.parse(((await obj.json()) as { generated?: string }).generated ?? "");
      generated = Number.isFinite(t) ? t : null;
    } catch {
      generated = null;
    }
  }
  generatedMemo.set(env.FEED, { at: Date.now(), generated });
  return generated;
}

function etagMatches(header: string | null, etag: string): boolean {
  if (!header) return false;
  return header.split(",").some((t) => {
    const tag = t.trim().replace(/^W\//, "");
    return tag === "*" || tag === etag;
  });
}

export async function serveFeedFile(req: Request, path: string, env: Env, ctx: ExecutionContext): Promise<Response> {
  const [file, generated] = await Promise.all([
    getFeedFile(path, env, new URL(req.url).origin, ctx, req.headers),
    publishedAt(env),
  ]);
  const cors = { "access-control-allow-origin": "*", "access-control-expose-headers": "etag, x-mirage-feed-age" };
  if (file.status === 404) return new Response("not found\n", { status: 404, headers: { ...cors, "content-type": TEXT } });
  if (file.status !== 200 && file.status !== 304) {
    return new Response("upstream unavailable, retry later\n", {
      status: 502,
      headers: { ...cors, "content-type": TEXT, "retry-after": "300" },
    });
  }

  const etag = file.headers.get("etag") ?? "";
  const headers = new Headers({
    ...cors,
    "content-type": file.headers.get("content-type") ?? TEXT,
    etag,
    "cache-control": isShadow(env) ? "private, no-store" : `public, max-age=${FRESH_TTL}`,
  });
  if (generated !== null) headers.set("x-mirage-feed-age", String(Math.max(0, Math.floor((Date.now() - generated) / 1000))));
  if (file.headers.has(STALE)) headers.set(STALE, "1");

  const notModified = file.status === 304 || etagMatches(req.headers.get("if-none-match"), etag);
  return new Response(notModified ? null : file.body, { status: notModified ? 304 : 200, headers });
}
