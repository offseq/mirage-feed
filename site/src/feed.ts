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
  png: "image/png",
};

const DIR_RE = /^(?:latest(?:\/(?:stix|zeek|suricata(?:\/datasets)?|mikrotik|nft|ipset|crowdsec|defender))?|misp|schema)$/;
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
// Always eligible for the GitHub fallback: they are not listed in feed.json, and feed.json itself is needed to read the list.
const ROOT_FILES = new Set(["feed.json", "stats.json", "history.json", "SHA256SUMS", "SHA256SUMS.minisig"]);

export const FRESH_TTL = 3600;
export const STALE_TTL = 48 * 3600;
export const MISSING_TTL = 300;
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

const listedMemo = new WeakMap<R2Bucket, { at: number; paths: Set<string> }>();

// null when the index itself is unreadable, so an outage is not mistaken for a missing file.
async function isListed(path: string, env: Env, origin: string, ctx: ExecutionContext): Promise<boolean | null> {
  if (ROOT_FILES.has(path)) return true;
  let listed = listedMemo.get(env.FEED);
  if (!listed || Date.now() - listed.at > META_TTL_MS) {
    const feed = await getFeedJson<{ files?: { path?: string }[] }>("feed.json", env, origin, ctx);
    if (!feed) return null;
    listed = { at: Date.now(), paths: new Set((feed.files ?? []).map((f) => f.path ?? "")) };
    listedMemo.set(env.FEED, listed);
  }
  return listed.paths.has(path);
}

// R2 is the source of truth. GitHub is consulted only when R2 errors, and only for files the current index lists,
// so random names cannot multiply origin traffic.
export async function getFeedFile(path: string, env: Env, origin: string, ctx: ExecutionContext): Promise<Response> {
  const cache = caches.default;
  const freshKey = cacheKey(origin, "fresh", path);

  const hit = await cache.match(freshKey);
  if (hit) return hit.headers.has(MISSING) ? new Response(null, { status: 404 }) : hit;

  const type = contentType(path) ?? TEXT;
  const missing = () => {
    ctx.waitUntil(cache.put(freshKey, new Response("", { headers: { [MISSING]: "1", "cache-control": `max-age=${MISSING_TTL}` } })));
    return new Response(null, { status: 404 });
  };

  let obj: R2ObjectBody | null = null;
  let failed = false;
  try {
    obj = await env.FEED.get(path);
  } catch {
    failed = true;
  }
  if (obj) {
    const headers = { "content-type": type, etag: obj.httpEtag, "last-modified": obj.uploaded.toUTCString(), "content-length": String(obj.size) };
    const body = await obj.arrayBuffer();
    ctx.waitUntil(cache.put(freshKey, withTtl(body, headers, FRESH_TTL)));
    return new Response(body, { headers });
  }
  if (!failed) return missing();
  const known = await isListed(path, env, origin, ctx);
  if (known === false) return missing();

  const staleKey = cacheKey(origin, "stale", path);
  const upstream = known ? await fromRaw(env, path) : null;
  if (upstream?.ok) {
    const body = await upstream.arrayBuffer();
    const headers: Record<string, string> = { "content-type": type, etag: await sha256Etag(body), "content-length": String(body.byteLength) };
    const modified = upstream.headers.get("last-modified");
    if (modified) headers["last-modified"] = modified;
    ctx.waitUntil(Promise.all([cache.put(freshKey, withTtl(body, headers, FRESH_TTL)), cache.put(staleKey, withTtl(body, headers, STALE_TTL))]));
    return new Response(body, { headers });
  }
  if (upstream?.status === 404) return missing();

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
  try {
    const obj = await env.FEED.get("_meta/published.json");
    const t = Date.parse(((await obj?.json()) as { generated?: string } | undefined)?.generated ?? "");
    generated = Number.isFinite(t) ? t : null;
  } catch {
    generated = null;
  }
  generatedMemo.set(env.FEED, { at: Date.now(), generated });
  return generated;
}

function etagMatches(header: string | null, etag: string): boolean {
  if (!header || !etag) return false;
  return header.split(",").some((t) => {
    const tag = t.trim().replace(/^W\//, "");
    return tag === "*" || tag === etag;
  });
}

function notModified(req: Request, etag: string, lastModified: string | null): boolean {
  const inm = req.headers.get("if-none-match");
  if (inm !== null) return etagMatches(inm, etag);
  const since = Date.parse(req.headers.get("if-modified-since") ?? "");
  const modified = Date.parse(lastModified ?? "");
  return Number.isFinite(since) && Number.isFinite(modified) && modified <= since;
}

type Ranged = { offset: number; length: number } | "unsatisfiable" | null;

// One range only; a multi-range or malformed header is ignored and the full body is sent, as RFC 9110 allows.
export function parseRange(header: string | null, size: number): Ranged {
  const m = /^bytes=(\d*)-(\d*)$/.exec(header?.trim() ?? "");
  if (!m || (m[1] === "" && m[2] === "")) return null;
  let start: number;
  let end: number;
  if (m[1] === "") {
    const suffix = Number(m[2]);
    if (suffix === 0) return "unsatisfiable";
    start = Math.max(0, size - suffix);
    end = size - 1;
  } else {
    start = Number(m[1]);
    end = m[2] === "" ? size - 1 : Math.min(Number(m[2]), size - 1);
    if (m[2] !== "" && Number(m[2]) < start) return null;
  }
  return start >= size ? "unsatisfiable" : { offset: start, length: end - start + 1 };
}

const CORS = {
  "access-control-allow-origin": "*",
  "access-control-expose-headers": "etag, last-modified, content-range, accept-ranges, x-mirage-feed-age",
};

export async function serveFeedFile(req: Request, path: string, env: Env, ctx: ExecutionContext): Promise<Response> {
  const [file, generated] = await Promise.all([getFeedFile(path, env, new URL(req.url).origin, ctx), publishedAt(env)]);
  if (file.status === 404) {
    return new Response("not found\n", { status: 404, headers: { ...CORS, "content-type": TEXT, "cache-control": `public, max-age=${MISSING_TTL}` } });
  }
  if (!file.ok) {
    return new Response("upstream unavailable, retry later\n", {
      status: 502,
      headers: { ...CORS, "content-type": TEXT, "cache-control": "no-store", "retry-after": "300" },
    });
  }

  const etag = file.headers.get("etag") ?? "";
  const lastModified = file.headers.get("last-modified");
  const headers = new Headers({
    ...CORS,
    "content-type": file.headers.get("content-type") ?? TEXT,
    etag,
    "cache-control": isShadow(env) ? "private, no-store" : `public, max-age=${FRESH_TTL}`,
    "accept-ranges": "bytes",
    "x-robots-tag": "noindex",
  });
  if (lastModified) headers.set("last-modified", lastModified);
  if (generated !== null) headers.set("x-mirage-feed-age", String(Math.max(0, Math.floor((Date.now() - generated) / 1000))));
  if (file.headers.has(STALE)) headers.set(STALE, "1");

  if (notModified(req, etag, lastModified)) return new Response(null, { status: 304, headers });

  const rangeHeader = req.method === "GET" ? req.headers.get("range") : null;
  const ifRange = req.headers.get("if-range");
  if (!rangeHeader || (ifRange !== null && ifRange !== etag)) {
    const length = file.headers.get("content-length");
    if (length) headers.set("content-length", length);
    return new Response(file.body, { status: 200, headers });
  }
  // Ranges are sliced from the full object, which the edge cache already holds after the first read.
  const body = await file.arrayBuffer();
  const r = parseRange(rangeHeader, body.byteLength);
  if (r === "unsatisfiable") {
    headers.set("content-range", `bytes */${body.byteLength}`);
    headers.set("cache-control", "no-store");
    return new Response(null, { status: 416, headers });
  }
  if (r) {
    headers.set("content-range", `bytes ${r.offset}-${r.offset + r.length - 1}/${body.byteLength}`);
    headers.set("content-length", String(r.length));
    return new Response(body.slice(r.offset, r.offset + r.length), { status: 206, headers });
  }
  headers.set("content-length", String(body.byteLength));
  return new Response(body, { status: 200, headers });
}
