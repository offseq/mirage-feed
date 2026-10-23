import { ASSETS, OG_FALLBACK } from "./assets";
import { isShadow, type Env } from "./env";
import { getFeedFile, getFeedJson, isAllowedPath, serveFeedFile } from "./feed";
import { STALE_AFTER_H, datasetLd, renderHome, type FeedIndex, type Stats } from "./home";
import { ISO, SITE, layout, num } from "./html";
import { MINISIGN_PUB, renderAtom, securityTxt, type HistoryRow } from "./meta";
import { lookup, lookupForm, parseAddr, renderLookup, type Lookup } from "./lookup";
import { PRIVACY_UPDATED, REMOVAL_SENT, type RemovalForm, renderNotFound, renderPrivacy, renderRemoval, renderRemovalSent } from "./pages";
import { TooLarge, forwardRemoval, readRemoval, validate, verifyTurnstile, type RemovalInput } from "./removal";
import { authorized, challenge, secure, type Kind } from "./security";

const DESCRIPTION =
  "Free daily threat intelligence from the OffSeq Mirage honeypot fleet: handshake-verified attacker IPs, exploited CVEs, payload URLs and fingerprints. CC BY 4.0, TLP:CLEAR.";
const PUBLIC_PATHS = new Set(["/robots.txt", "/security.txt", "/.well-known/security.txt", "/.well-known/mirage-feed-minisign.pub"]);
const TEXT = "text/plain; charset=utf-8";
const NO_STORE = "no-store";
const BRAND = "0b6e8a";

const text = (body: string, type: string, status = 200, extra: Record<string, string> = {}) =>
  new Response(body, { status, headers: { "content-type": type, ...extra } });

const redirect = (location: string, status = 302) => new Response(null, { status, headers: { location } });

const json = (body: unknown, status: number, cache: string, extra: Record<string, string> = {}) =>
  Response.json(body, { status, headers: { "cache-control": cache, "access-control-allow-origin": "*", ...extra } });

function uaFamily(ua: string): string {
  const families: [RegExp, string][] = [
    [/pfblocker|pfsense/i, "pfsense"],
    [/opnsense/i, "opnsense"],
    [/fortigate|fortinet|fortios/i, "fortinet"],
    [/pan-os|palo ?alto/i, "paloalto"],
    [/mikrotik|routeros/i, "mikrotik"],
    [/misp/i, "misp"],
    [/opencti/i, "opencti"],
    [/crowdsec/i, "crowdsec"],
    [/^curl\//i, "curl"],
    [/^wget/i, "wget"],
    [/python|aiohttp|httpx/i, "python"],
    [/^go-http-client/i, "go"],
    [/mozilla\//i, "browser"],
  ];
  return families.find(([re]) => re.test(ua))?.[1] ?? (ua ? "other" : "none");
}

const isPrefetch = (req: Request) => /prefetch|prerender/i.test(req.headers.get("sec-purpose") ?? req.headers.get("purpose") ?? "");

// Aggregate counters only: the client IP, full user agent and looked-up address are never written.
function count(req: Request, env: Env, path: string, detail?: string) {
  if (req.method !== "GET" || isPrefetch(req)) return;
  const cf = (req as Request & { cf?: { asn?: number; country?: string } }).cf;
  env.FETCHES?.writeDataPoint({
    indexes: [path.slice(0, 96)],
    blobs: [path, String(cf?.asn ?? ""), cf?.country ?? "", detail ?? uaFamily(req.headers.get("user-agent") ?? "")],
    doubles: [1],
  });
}

interface PageOpts {
  status?: number;
  day?: string;
  head?: string;
  description?: string;
  noindex?: boolean;
  canonical?: boolean;
  cache?: string;
}

function page(env: Env, path: string, title: string, body: string, o: PageOpts = {}): Response {
  const html = layout({
    title,
    description: o.description ?? DESCRIPTION,
    path,
    body,
    shadow: isShadow(env),
    day: o.day,
    head: o.head,
    noindex: o.noindex,
    canonical: o.canonical,
  });
  const headers: Record<string, string> = { "cache-control": isShadow(env) ? "private, no-store" : (o.cache ?? "public, max-age=300") };
  if (o.noindex) headers["x-robots-tag"] = "noindex";
  return text(html, "text/html; charset=utf-8", o.status ?? 200, headers);
}

const TURNSTILE_JS = '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>';
const removalPage = (env: Env, form: RemovalForm = {}, status = 200) =>
  page(env, "/removal", `${form.error ? "Error: " : ""}Removal request`, renderRemoval(form, env.TURNSTILE_SITEKEY), {
    status,
    head: TURNSTILE_JS,
    description: "Ask for an IP address to be taken out of the Mirage Feed. No account needed; requests are answered within 72 hours.",
  });

async function snapshot(req: Request, env: Env, ctx: ExecutionContext): Promise<{ feed: FeedIndex | null; stats: Stats | null }> {
  const origin = new URL(req.url).origin;
  const [feed, rawStats] = await Promise.all([
    getFeedJson<FeedIndex>("feed.json", env, origin, ctx),
    getFeedJson<Stats & { stats?: Stats }>("stats.json", env, origin, ctx),
  ]);
  return { feed, stats: rawStats?.stats ?? rawStats ?? feed?.stats ?? null };
}

async function home(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const { feed, stats } = await snapshot(req, env, ctx);
  return page(env, "/", "Mirage Feed: daily honeypot threat intelligence", renderHome(feed, stats, Date.now()), {
    day: feed?.day,
    head: datasetLd(feed),
  });
}

function ageSeconds(generated: string | undefined): number | null {
  const t = Date.parse(generated ?? "");
  return Number.isFinite(t) ? Math.max(0, Math.floor((Date.now() - t) / 1000)) : null;
}

async function statusJson(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const { feed, stats } = await snapshot(req, env, ctx);
  const age = ageSeconds(feed?.generated);
  const stale = age === null || age > STALE_AFTER_H * 3600;
  const pub = stats?.published ?? {};
  const body = {
    generated: feed?.generated ?? null,
    day: feed?.day ?? null,
    age_seconds: age,
    stale,
    counts: { ips_7d: pub.ips ?? null, active_24h: pub.active_24h ?? null, scanners: pub.scanners ?? null, cves: pub.cves ?? null },
  };
  return json(body, stale ? 503 : 200, NO_STORE);
}

function ago(seconds: number): string {
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 172_800) return `${Math.floor(seconds / 3600)} h ago`;
  return `${Math.floor(seconds / 86_400)} days ago`;
}

async function badge(req: Request, env: Env, ctx: ExecutionContext, which: "freshness" | "ips"): Promise<Response> {
  const { feed, stats } = await snapshot(req, env, ctx);
  let body: { label: string; message: string; color: string };
  if (which === "freshness") {
    const age = ageSeconds(feed?.generated);
    body = { label: "updated", message: age === null ? "unknown" : ago(age), color: age === null || age > STALE_AFTER_H * 3600 ? "red" : BRAND };
  } else {
    const ips = stats?.published?.ips;
    body = { label: "attacker IPs, 7 d", message: typeof ips === "number" ? num(ips) : "unknown", color: typeof ips === "number" ? BRAND : "lightgrey" };
  }
  return json({ schemaVersion: 1, ...body }, 200, "public, max-age=300");
}


async function atom(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const history = await getFeedJson<HistoryRow[]>("history.json", env, new URL(req.url).origin, ctx);
  return text(renderAtom(history, Date.now()), "application/atom+xml; charset=utf-8", 200, { "cache-control": "public, max-age=3600" });
}

// The embedded card keeps link previews working before the first build and while R2 is unavailable.
async function og(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const res = await getFeedFile("og.png", env, new URL(req.url).origin, ctx);
  return new Response(res.ok ? res.body : OG_FALLBACK, { headers: { "content-type": "image/png", "cache-control": "public, max-age=3600" } });
}

const LOOKUP_DESCRIPTION = "Check whether an IP address is in the Mirage Feed, with its sightings, network, services and ATT&CK techniques.";

// no-transform stops Cloudflare injecting its analytics beacon, which would report the looked-up address in the URL.
function lookupPage(env: Env, path: string, title: string, body: string, status = 200, cache = "private, max-age=300"): Response {
  const res = page(env, path, title, body, { status, noindex: true, canonical: false, description: LOOKUP_DESCRIPTION, cache });
  res.headers.set("cache-control", `${res.headers.get("cache-control")}, no-transform`);
  return res;
}

async function ipLookup(req: Request, env: Env, ctx: ExecutionContext, path: string): Promise<Response> {
  const url = new URL(req.url);
  if (path === "/ip") {
    const raw = url.searchParams.get("addr");
    if (raw === null) return lookupPage(env, path, "Look up an address", `<section aria-labelledby="h-ip"><h1 id="h-ip">Look up an address</h1>\n${lookupForm()}\n</section>`);
    const addr = parseAddr(raw);
    if (addr) return redirect(`/ip/${addr.slug}`);
    const error = "Enter one public IPv4 address, or an IPv6 address or /64.";
    return lookupPage(env, path, "Error: Look up an address", `<section aria-labelledby="h-ip"><h1 id="h-ip">Look up an address</h1>\n${lookupForm(raw.slice(0, 64), error)}\n</section>`, 400, NO_STORE);
  }

  let segment: string;
  try {
    segment = decodeURIComponent(path.slice(4));
  } catch {
    segment = "";
  }
  const wantsJson = segment.endsWith(".json");
  const input = wantsJson ? segment.slice(0, -5) : segment;
  const addr = parseAddr(input);
  const fail = (status: number, error: string, extra: Record<string, string> = {}) =>
    wantsJson
      ? json({ error }, status, NO_STORE, { "x-robots-tag": "noindex", ...extra })
      : withHeaders(lookupPage(env, path, "Error: Look up an address", `<section aria-labelledby="h-ip"><h1 id="h-ip">Look up an address</h1>\n${lookupForm(input.slice(0, 64), error)}\n</section>`, status, NO_STORE), extra);
  if (!addr) return fail(400, "Not a public IPv4 address, IPv6 address or IPv6 /64.");
  if (addr.slug !== input) return redirect(`/ip/${addr.slug}${wantsJson ? ".json" : ""}`, 301);

  if (env.LOOKUP_LIMIT && !(await env.LOOKUP_LIMIT.limit({ key: req.headers.get("cf-connecting-ip") ?? "" })).success) {
    return fail(429, "Too many lookups from your network. Try again in a minute.", { "retry-after": "60" });
  }
  const result = await lookup(addr, env, url.origin, ctx);
  if (!result) return fail(503, "Lookup data is not available right now. Try again later.", { "retry-after": "300" });
  count(req, env, "/ip", outcome(result));
  if (wantsJson) return json(result, 200, "private, max-age=300", { "x-robots-tag": "noindex" });
  return lookupPage(env, path, `${addr.value} in the Mirage Feed`, renderLookup(result));
}

const outcome = (l: Lookup) => (l.scanner ? "scanner" : l.anonymizer && !l.listed ? "anonymizer" : l.listed ? "listed" : "not-listed");

function withHeaders(res: Response, extra: Record<string, string>): Response {
  for (const [k, v] of Object.entries(extra)) res.headers.set(k, v);
  return res;
}

async function removal(req: Request, env: Env): Promise<Response> {
  const wantsJson = (req.headers.get("accept") ?? "").includes("application/json");
  const origin = req.headers.get("origin");
  if (origin && origin !== new URL(req.url).origin) return text("Forbidden.\n", TEXT, 403);

  const clientIp = req.headers.get("cf-connecting-ip") ?? "";
  let input: RemovalInput = { ip: "", email: "", reason: "", website: "", token: "" };
  const fail = (status: number, error: string, field?: string) =>
    wantsJson ? Response.json({ ok: false, error, field }, { status }) : removalPage(env, { ...input, error, field }, status);

  if (env.REMOVAL_LIMIT && !(await env.REMOVAL_LIMIT.limit({ key: clientIp })).success) {
    return withHeaders(fail(429, "Too many requests from your network. Try again later, or write to abuse@offseq.com."), { "retry-after": "60" });
  }
  try {
    input = await readRemoval(req);
  } catch (e) {
    if (e instanceof TooLarge) return text("Too large.\n", TEXT, 413);
    throw e;
  }

  const check = validate(input);
  if (!check.ok) return fail(400, check.error, check.field);
  // Bots that fill the hidden field get the normal success response and nothing is forwarded.
  if (!input.website) {
    if (!(await verifyTurnstile(input.token, clientIp, env))) {
      return fail(400, "The anti-abuse check did not complete. It needs JavaScript; without it, write to abuse@offseq.com.");
    }
    const sent = await forwardRemoval(input, clientIp, env);
    if (!sent.ok) return fail(sent.status, sent.error);
  }
  return wantsJson ? Response.json({ ok: true, message: REMOVAL_SENT }) : redirect("/removal/sent", 303);
}

function robots(env: Env): string {
  return isShadow(env) ? "User-agent: *\nDisallow: /\n" : `User-agent: *\nAllow: /\nSitemap: ${SITE}/sitemap.xml\n`;
}

async function sitemap(req: Request, env: Env, ctx: ExecutionContext): Promise<string> {
  const feed = await getFeedJson<FeedIndex>("feed.json", env, new URL(req.url).origin, ctx);
  const day = ISO.test(feed?.generated ?? "") ? feed!.generated!.slice(0, 10) : null;
  const urls: [string, string | null][] = [["/", day], ["/removal", null], ["/privacy", PRIVACY_UPDATED]];
  return `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.map(([p, mod]) => `<url><loc>${SITE}${p}</loc>${mod ? `<lastmod>${mod}</lastmod>` : ""}</url>`).join("\n")}
</urlset>
`;
}



const FEED_ROOT = new Set(["/feed.json", "/stats.json", "/history.json"]);

function allowFor(path: string, feedPath: string | null): string {
  if (path === "/removal") return "GET, HEAD, POST";
  return feedPath !== null ? "GET, HEAD, OPTIONS" : "GET, HEAD";
}

async function route(req: Request, env: Env, ctx: ExecutionContext, path: string): Promise<[Response, Kind]> {
  const method = req.method;

  if (path === "/removal" && method === "POST") {
    const res = withHeaders(await removal(req, env), { "cache-control": NO_STORE, vary: "Accept" });
    return [res, "removal"];
  }

  const feedPath = path.startsWith("/mirage-feed/") ? path.slice(13) : FEED_ROOT.has(path) ? path.slice(1) : null;
  if (feedPath !== null && method === "OPTIONS") {
    return [
      new Response(null, {
        status: 204,
        headers: {
          "access-control-allow-origin": "*",
          "access-control-allow-methods": "GET, HEAD, OPTIONS",
          "access-control-allow-headers": "If-None-Match, If-Modified-Since, Range",
          "access-control-max-age": "86400",
        },
      }),
      "feed",
    ];
  }
  if (method !== "GET" && method !== "HEAD") {
    return [text("Method not allowed.\n", TEXT, 405, { allow: allowFor(path, feedPath), "cache-control": NO_STORE }), "asset"];
  }

  if (path === "/mirage-feed" || path === "/mirage-feed/" || path === "/mirage-feed/latest" || path === "/mirage-feed/latest/") {
    return [redirect("/#files"), "asset"];
  }
  if (path === "/mirage-feed/misp" || path === "/mirage-feed/misp/") return [redirect("/mirage-feed/misp/manifest.json"), "asset"];
  if (feedPath !== null && isAllowedPath(feedPath)) {
    const res = await serveFeedFile(req, feedPath, env, ctx);
    if (res.status === 200 || res.status === 206 || res.status === 304) count(req, env, feedPath);
    return [res, "feed"];
  }
  if (path === "/ip" || path.startsWith("/ip/")) return [await ipLookup(req, env, ctx, path), "lookup"];

  const static_ = ASSETS[path];
  if (static_) {
    const cache = static_.immutable ? "public, max-age=31536000, immutable" : "public, max-age=86400";
    return [new Response(static_.body, { headers: { "content-type": static_.type, "cache-control": cache } }), "asset"];
  }

  const hour = { "cache-control": "public, max-age=3600" };
  switch (path) {
    case "/":
      return [await home(req, env, ctx), "page"];
    case "/removal": {
      const ip = new URL(req.url).searchParams.get("ip")?.trim().slice(0, 64);
      return [removalPage(env, ip ? { ip } : {}), "removal"];
    }
    case "/removal/sent":
      return [page(env, path, "Request received", renderRemovalSent(), { noindex: true, description: REMOVAL_SENT }), "page"];
    case "/privacy":
      return [
        page(env, path, "Privacy notice", renderPrivacy(), {
          description: "How the Mirage Feed and feeds.offseq.com handle personal data: what is published, the legal basis, retention and your rights under the GDPR.",
        }),
        "page",
      ];
    case "/status.json":
      return [await statusJson(req, env, ctx), "feed"];
    case "/badge/freshness.json":
      return [await badge(req, env, ctx, "freshness"), "feed"];
    case "/badge/ips.json":
      return [await badge(req, env, ctx, "ips"), "feed"];
    case "/feed.atom":
      return [await atom(req, env, ctx), "feed"];
    case "/og.png":
      return [await og(req, env, ctx), "feed"];
    case "/robots.txt":
      return [text(robots(env), TEXT, 200, hour), "asset"];
    case "/sitemap.xml":
      return [text(await sitemap(req, env, ctx), "application/xml; charset=utf-8", 200, hour), "asset"];
    case "/security.txt":
      return [redirect("/.well-known/security.txt", 301), "asset"];
    case "/.well-known/security.txt":
      return [text(securityTxt(Date.now()), TEXT, 200, hour), "asset"];
    case "/.well-known/mirage-feed-minisign.pub":
      return [text(MINISIGN_PUB, TEXT, 200, { "cache-control": "public, max-age=86400", "access-control-allow-origin": "*" }), "feed"];
  }
  return [
    page(env, path, "Not found", renderNotFound(path), {
      status: 404,
      canonical: false,
      description: "Page not found on feeds.offseq.com, the home of the OffSeq Mirage community threat feed.",
    }),
    "page",
  ];
}

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const path = new URL(req.url).pathname.replace(/\/{2,}/g, "/");
    if (isShadow(env) && !PUBLIC_PATHS.has(path) && !(await authorized(req, env))) {
      return secure(challenge(), env, "asset");
    }
    const [res, kind] = await route(req, env, ctx, path);
    const out = await secure(res, env, kind);
    return req.method === "HEAD" ? new Response(null, out) : out;
  },
} satisfies ExportedHandler<Env>;
