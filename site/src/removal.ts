import { parseAddr } from "./addr";
import type { Env } from "./env";

const EMAIL = /^[^\s@<>"]{1,64}@[^\s@<>"]+\.[^\s@<>".]{2,}$/;
export const MAX_BODY = 8192;
const TURNSTILE_HOST = "feeds.offseq.com";
export const REASON_MIN = 20;
export const REASON_MAX = 2000;

export interface RemovalInput {
  ip: string;
  email: string;
  reason: string;
  website: string;
  token: string;
}

// On success, ip is the address as the feed lists it: IPv6 as its /64.
export type Check = { ok: true; ip: string } | { ok: false; field: "ip" | "email" | "reason"; error: string };

export function validate(r: RemovalInput): Check {
  const addr = parseAddr(r.ip);
  if (!addr) {
    return { ok: false, field: "ip", error: "Enter one public IPv4 address, or an IPv6 address or /64 as listed." };
  }
  if (r.email.length > 254 || !EMAIL.test(r.email)) return { ok: false, field: "email", error: "Enter an email address we can reply to." };
  if (r.reason.length < REASON_MIN || r.reason.length > REASON_MAX) {
    return { ok: false, field: "reason", error: `Give a reason between ${REASON_MIN} and ${REASON_MAX.toLocaleString("en-US")} characters.` };
  }
  return { ok: true, ip: addr.value };
}

export class TooLarge extends Error {}

export async function readCapped(req: Request, limit = MAX_BODY): Promise<string> {
  if (!req.body) return "";
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > limit) {
      await reader.cancel();
      throw new TooLarge();
    }
    chunks.push(value);
  }
  const buf = new Uint8Array(size);
  let at = 0;
  for (const c of chunks) {
    buf.set(c, at);
    at += c.byteLength;
  }
  return new TextDecoder().decode(buf);
}

export async function readRemoval(req: Request): Promise<RemovalInput> {
  const text = await readCapped(req);
  let raw: Record<string, unknown> = {};
  if ((req.headers.get("content-type") ?? "").includes("application/json")) {
    try {
      const parsed: unknown = JSON.parse(text);
      if (parsed && typeof parsed === "object") raw = parsed as Record<string, unknown>;
    } catch {
      raw = {};
    }
  } else {
    raw = Object.fromEntries(new URLSearchParams(text));
  }
  const str = (k: string) => (typeof raw[k] === "string" ? (raw[k] as string).trim() : "");
  return { ip: str("ip"), email: str("email"), reason: str("reason"), website: str("website"), token: str("cf-turnstile-response") };
}

export async function verifyTurnstile(token: string, clientIp: string, env: Env): Promise<boolean> {
  if (!token || !env.TURNSTILE_SECRET) return false;
  try {
    const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      body: new URLSearchParams({ secret: env.TURNSTILE_SECRET, response: token, remoteip: clientIp }),
      signal: AbortSignal.timeout(10_000),
    });
    const j = (await res.json()) as { success?: boolean; hostname?: string; action?: string };
    return j.success === true && j.hostname === TURNSTILE_HOST && j.action === "removal";
  } catch {
    return false;
  }
}

export type Forwarded = { ok: true } | { ok: false; status: number; error: string };

const UPSTREAM_DOWN = "We could not record the request. Try again, or write to abuse@offseq.com.";

export async function forwardRemoval(r: RemovalInput, clientIp: string, env: Env): Promise<Forwarded> {
  if (!env.FEED_PROXY_SECRET) return { ok: false, status: 502, error: UPSTREAM_DOWN };
  let res: Response;
  try {
    res = await fetch(env.REMOVAL_UPSTREAM, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json",
        "x-feed-proxy-secret": env.FEED_PROXY_SECRET,
        "x-feed-client-ip": clientIp,
      },
      body: JSON.stringify({ ip: r.ip, email: r.email, reason: r.reason, website: r.website }),
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    return { ok: false, status: 502, error: UPSTREAM_DOWN };
  }
  if (res.ok) return { ok: true };
  const detail = await res
    .json()
    .then((d) => (d as { detail?: unknown }).detail)
    .catch(() => undefined);
  if (res.status >= 400 && res.status < 500 && typeof detail === "string" && detail.length <= 300) {
    return { ok: false, status: res.status === 429 ? 429 : 400, error: detail };
  }
  return { ok: false, status: 502, error: UPSTREAM_DOWN };
}
