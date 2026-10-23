import { isShadow, type Env } from "./env";
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

export type Kind = "page" | "removal" | "file";

const TURNSTILE = "https://challenges.cloudflare.com";

export async function pageCsp(turnstile = false): Promise<string> {
  return [
    "default-src 'none'",
    `script-src 'self'${turnstile ? ` ${TURNSTILE}` : ""}`,
    ...(turnstile ? [`frame-src ${TURNSTILE}`] : []),
    `style-src ${await cssHash()}`,
    "font-src 'self'",
    "img-src 'self'",
    "connect-src 'self'",
    "form-action 'self'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
  ].join("; ");
}

const FILE_CSP = "default-src 'none'; frame-ancestors 'none'; sandbox";

export async function secure(res: Response, env: Env, kind: Kind): Promise<Response> {
  const out = new Response(res.body, res);
  const h = out.headers;
  h.set("content-security-policy", kind === "file" ? FILE_CSP : await pageCsp(kind === "removal"));
  h.set("strict-transport-security", "max-age=63072000; includeSubDomains");
  h.set("x-content-type-options", "nosniff");
  h.set("referrer-policy", "strict-origin-when-cross-origin");
  h.set("permissions-policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=()");
  h.set("x-frame-options", "DENY");
  h.set("cross-origin-opener-policy", "same-origin");
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
