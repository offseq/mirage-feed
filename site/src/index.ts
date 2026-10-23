import { APP_JS } from "./app";
import { isShadow, type Env } from "./env";
import { getFeedJson, isAllowedPath, serveFeedFile } from "./feed";
import { renderHome, type FeedIndex, type Stats } from "./home";
import { SITE, layout } from "./html";
import { REMOVAL_SENT, type RemovalForm, renderNotFound, renderPrivacy, renderRemoval, renderRemovalSent } from "./pages";
import { TooLarge, forwardRemoval, readRemoval, validate, verifyTurnstile, type RemovalInput } from "./removal";
import { authorized, challenge, secure, type Kind } from "./security";
import plex400 from "../fonts/ibm-plex-mono-latin-400-normal.woff2";
import plex600 from "../fonts/ibm-plex-mono-latin-600-normal.woff2";

const DESCRIPTION =
  "Free daily threat intelligence from the OffSeq Mirage honeypot fleet: handshake-verified attacker IPs, exploited CVEs, payload URLs and fingerprints. CC BY 4.0, TLP:CLEAR.";
const SECURITY_TXT_EXPIRES = "2027-10-23T00:00:00.000Z";
const PUBLIC_PATHS = new Set(["/robots.txt", "/.well-known/security.txt"]);

const FAVICON = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><rect width="16" height="16" fill="#0b6e8a"/><path d="M3 12V4h2l3 4 3-4h2v8h-2V7.5L8 11 5 7.5V12z" fill="#fff"/></svg>`;

const text = (body: string, type: string, status = 200, extra: Record<string, string> = {}) =>
  new Response(body, { status, headers: { "content-type": type, ...extra } });

const asset = (body: BodyInit, type: string) =>
  new Response(body, { headers: { "content-type": type, "cache-control": "public, max-age=86400" } });

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

// Aggregate counters only: the client IP and full user agent are never written.
function countFetch(req: Request, path: string, env: Env) {
  const cf = (req as Request & { cf?: { asn?: number; country?: string } }).cf;
  env.FETCHES?.writeDataPoint({
    indexes: [path.slice(0, 96)],
    blobs: [path, String(cf?.asn ?? ""), cf?.country ?? "", uaFamily(req.headers.get("user-agent") ?? "")],
    doubles: [1],
  });
}

interface PageOpts {
  status?: number;
  day?: string;
  head?: string;
}

function page(env: Env, path: string, title: string, body: string, o: PageOpts = {}): Response {
  const html = layout({ title, description: DESCRIPTION, path, body, shadow: isShadow(env), day: o.day, head: o.head });
  return text(html, "text/html; charset=utf-8", o.status ?? 200, {
    "cache-control": isShadow(env) ? "private, no-store" : "public, max-age=300",
  });
}

const TURNSTILE_JS = '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>';
const removalPage = (env: Env, form: RemovalForm = {}, status = 200) =>
  page(env, "/removal", "Removal request", renderRemoval(form, env.TURNSTILE_SITEKEY), { status, head: TURNSTILE_JS });

async function home(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const origin = new URL(req.url).origin;
  const [feed, rawStats] = await Promise.all([
    getFeedJson<FeedIndex>("feed.json", env, origin, ctx),
    getFeedJson<Stats & { stats?: Stats }>("stats.json", env, origin, ctx),
  ]);
  const stats = rawStats?.stats ?? rawStats ?? feed?.stats ?? null;
  return page(env, "/", "Mirage Feed: daily honeypot threat intelligence", renderHome(feed, stats, Date.now()), { day: feed?.day });
}

async function removal(req: Request, env: Env): Promise<Response> {
  const wantsJson = (req.headers.get("accept") ?? "").includes("application/json");
  const origin = req.headers.get("origin");
  if (origin && origin !== new URL(req.url).origin) return text("Forbidden.\n", "text/plain; charset=utf-8", 403);

  const clientIp = req.headers.get("cf-connecting-ip") ?? "";
  let input: RemovalInput = { ip: "", email: "", reason: "", website: "", token: "" };
  const fail = (status: number, error: string, field?: string) =>
    wantsJson ? Response.json({ ok: false, error, field }, { status }) : removalPage(env, { ...input, error, field }, status);

  if (env.REMOVAL_LIMIT && !(await env.REMOVAL_LIMIT.limit({ key: clientIp })).success) {
    return fail(429, "Too many requests from your network. Try again later, or write to abuse@offseq.com.");
  }
  try {
    input = await readRemoval(req);
  } catch (e) {
    if (e instanceof TooLarge) return text("Too large.\n", "text/plain; charset=utf-8", 413);
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
  return wantsJson
    ? Response.json({ ok: true, message: REMOVAL_SENT })
    : new Response(null, { status: 303, headers: { location: "/removal/sent" } });
}

function robots(env: Env): string {
  return isShadow(env) ? "User-agent: *\nDisallow: /\n" : `User-agent: *\nAllow: /\nSitemap: ${SITE}/sitemap.xml\n`;
}

const SITEMAP = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${["/", "/removal", "/privacy"].map((p) => `<url><loc>${SITE}${p}</loc></url>`).join("\n")}
</urlset>
`;

const SECURITY_TXT = `Contact: mailto:abuse@offseq.com
Policy: https://cvd.cert.lv/programs/view/101
Expires: ${SECURITY_TXT_EXPIRES}
Preferred-Languages: en, lv
Canonical: ${SITE}/.well-known/security.txt
`;

async function route(req: Request, env: Env, ctx: ExecutionContext, path: string): Promise<[Response, Kind]> {
  const method = req.method;

  if (path === "/removal" && method === "POST") return [await removal(req, env), "removal"];

  const feedPath = path.startsWith("/mirage-feed/") ? path.slice(13) : path === "/feed.json" || path === "/stats.json" ? path.slice(1) : null;
  if (feedPath !== null && method === "OPTIONS") {
    return [
      new Response(null, {
        status: 204,
        headers: {
          "access-control-allow-origin": "*",
          "access-control-allow-methods": "GET, HEAD, OPTIONS",
          "access-control-allow-headers": "If-None-Match",
          "access-control-max-age": "86400",
        },
      }),
      "file",
    ];
  }
  if (method !== "GET" && method !== "HEAD") {
    return [text("Method not allowed.\n", "text/plain; charset=utf-8", 405, { allow: "GET, HEAD" }), "file"];
  }

  if (path === "/mirage-feed" || path === "/mirage-feed/") return [Response.redirect(`${new URL(req.url).origin}/`, 301), "file"];
  if (path === "/mirage-feed/misp" || path === "/mirage-feed/misp/") {
    return [Response.redirect(`${new URL(req.url).origin}/mirage-feed/misp/manifest.json`, 302), "file"];
  }
  if (feedPath !== null && isAllowedPath(feedPath)) {
    const res = await serveFeedFile(req, feedPath, env, ctx);
    if (res.status === 200 || res.status === 304) countFetch(req, feedPath, env);
    return [res, "file"];
  }

  switch (path) {
    case "/":
      return [await home(req, env, ctx), "page"];
    case "/removal":
      return [removalPage(env), "removal"];
    case "/removal/sent":
      return [page(env, path, "Request received", renderRemovalSent()), "page"];
    case "/privacy":
      return [page(env, path, "Privacy notice", renderPrivacy()), "page"];
    case "/app.js":
      return [asset(APP_JS, "text/javascript; charset=utf-8"), "file"];
    case "/fonts/plex-mono-400.woff2":
      return [asset(plex400, "font/woff2"), "file"];
    case "/fonts/plex-mono-600.woff2":
      return [asset(plex600, "font/woff2"), "file"];
    case "/favicon.svg":
      return [asset(FAVICON, "image/svg+xml"), "file"];
    case "/robots.txt":
      return [text(robots(env), "text/plain; charset=utf-8"), "file"];
    case "/sitemap.xml":
      return [text(SITEMAP, "application/xml; charset=utf-8"), "file"];
    case "/.well-known/security.txt":
      return [text(SECURITY_TXT, "text/plain; charset=utf-8"), "file"];
  }
  return [page(env, path, "Not found", renderNotFound(path), { status: 404 }), "page"];
}

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const path = new URL(req.url).pathname.replace(/\/{2,}/g, "/");
    if (isShadow(env) && !PUBLIC_PATHS.has(path) && !(await authorized(req, env))) {
      return secure(challenge(), env, "file");
    }
    const [res, kind] = await route(req, env, ctx, path);
    const out = await secure(res, env, kind);
    return req.method === "HEAD" ? new Response(null, out) : out;
  },
} satisfies ExportedHandler<Env>;
