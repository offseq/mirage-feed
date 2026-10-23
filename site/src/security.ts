import { APP_PATH } from "./assets";
import { isShadow, type Env } from "./env";
import { SITE } from "./html";
import { CSS } from "./style";

let styleHash: Promise<string> | null = null;
function cssHash(): Promise<string> {
  styleHash ??= crypto.subtle.digest("SHA-256", new TextEncoder().encode(CSS)).then((d) => {
    let bin = "";
    for (const b of new Uint8Array(d)) bin += String.fromCharCode(b);
    return `'sha256-${btoa(bin)}'`;
  });
  return styleHash;
}

// page: HTML; removal: HTML with Turnstile; lookup: HTML without CSP reports, whose document URL would carry
// the looked-up address; feed: public cross-origin data; asset: same-origin static files.
export type Kind = "page" | "removal" | "lookup" | "feed" | "asset";

const TURNSTILE = "https://challenges.cloudflare.com";
// The report collector accepts the legacy report-uri format only; it answers 422 to Reporting API batches.
export const CSP_REPORT = "https://mirage.offseq.com/_t/csp";
const TRUSTED_TYPES = "require-trusted-types-for 'script'; trusted-types 'none'";

// Cloudflare injects its Web Analytics beacon into HTML; Plausible events go to the self-hosted collector.
const CF_BEACON = "https://static.cloudflareinsights.com";
const CF_RUM = "https://cloudflareinsights.com";
export const PLAUSIBLE = "https://in.ainalytic.net";

// Lookup pages get neither analytics origin nor a report endpoint, since their URL carries the looked-up address.
export async function pageCsp(turnstile = false, lookup = false): Promise<string> {
  return [
    "default-src 'none'",
    `script-src ${SITE}${APP_PATH}${lookup ? "" : ` ${CF_BEACON}`}${turnstile ? ` ${TURNSTILE}` : ""}`,
    ...(turnstile ? [`frame-src ${TURNSTILE}`] : []),
    `style-src ${await cssHash()}`,
    "font-src 'self'",
    "img-src 'self'",
    `connect-src 'self'${lookup ? "" : ` ${CF_RUM} ${PLAUSIBLE}`}`,
    "form-action 'self'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
    ...(turnstile ? [] : [TRUSTED_TYPES]),
    ...(lookup ? [] : [`report-uri ${CSP_REPORT}`]),
  ].join("; ");
}

const FILE_CSP = "default-src 'none'; frame-ancestors 'none'; sandbox";

// Standardized features from the W3C registry only; proposed and experimental names draw "invalid directive" warnings.
export const PERMISSIONS_POLICY = [
  "accelerometer", "autoplay", "bluetooth", "camera", "display-capture", "encrypted-media", "geolocation", "gyroscope",
  "hid", "idle-detection", "magnetometer", "microphone", "midi", "payment", "picture-in-picture",
  "publickey-credentials-get", "screen-wake-lock", "serial", "usb", "web-share", "xr-spatial-tracking",
].map((f) => `${f}=()`).join(", ");

export async function secure(res: Response, env: Env, kind: Kind): Promise<Response> {
  const out = new Response(res.body, res);
  const h = out.headers;
  const html = kind === "page" || kind === "removal" || kind === "lookup";
  h.set("content-security-policy", html ? await pageCsp(kind === "removal", kind === "lookup") : FILE_CSP);
  h.set("strict-transport-security", "max-age=63072000; includeSubDomains; preload");
  h.set("x-content-type-options", "nosniff");
  h.set("referrer-policy", "strict-origin-when-cross-origin");
  h.set("permissions-policy", PERMISSIONS_POLICY);
  h.set("x-frame-options", "DENY");
  h.set("cross-origin-opener-policy", "same-origin");
  h.set("cross-origin-resource-policy", kind === "feed" ? "cross-origin" : "same-origin");
  if (isShadow(env)) h.set("x-robots-tag", "noindex, nofollow");
  return out;
}

async function digest(s: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)));
}

// Compare digests so the check runs in constant time regardless of input length.
export async function authorized(req: Request, env: Env): Promise<boolean> {
  if (!env.SHADOW_AUTH) return false;
  const header = req.headers.get("authorization") ?? "";
  if (!header.startsWith("Basic ")) return false;
  let given: string;
  try {
    given = atob(header.slice(6).trim());
  } catch {
    return false;
  }
  const [a, b] = await Promise.all([digest(given), digest(env.SHADOW_AUTH)]);
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export const challenge = (): Response =>
  new Response("Authentication required.\n", {
    status: 401,
    headers: {
      "www-authenticate": 'Basic realm="mirage-feed preview", charset="UTF-8"',
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "no-store",
    },
  });
